nbuf = nbuf_head;
	while (nbuf) {
		struct dp_txrx_peer *txrx_peer;
		struct dp_peer *peer;
		uint16_t peer_id;
		uint8_t err_code;
		uint8_t *tlv_hdr;
		uint32_t peer_meta_data;
		dp_txrx_ref_handle txrx_ref_handle = NULL;
		rx_tlv_hdr = qdf_nbuf_data(nbuf);

		/*
		 * retrieve the wbm desc info from nbuf TLV, so we can
		 * handle error cases appropriately
		 */
		hal_rx_priv_info_get_from_tlv(soc->hal_soc, rx_tlv_hdr,
					      (uint8_t *)&wbm_err_info,
					      sizeof(wbm_err_info));

		peer_meta_data = hal_rx_tlv_peer_meta_data_get(soc->hal_soc,
							       rx_tlv_hdr);
		peer_id = dp_rx_peer_metadata_peer_id_get(soc, peer_meta_data);
		txrx_peer = dp_tgt_txrx_peer_get_ref_by_id(soc, peer_id,
							   &txrx_ref_handle,
							   DP_MOD_ID_RX_ERR);

		if (!txrx_peer)
			dp_info_rl("peer is null peer_id%u err_src%u err_rsn%u",
				   peer_id, wbm_err_info.wbm_err_src,
				   wbm_err_info.reo_psh_rsn);

		/* Set queue_mapping in nbuf to 0 */
		dp_set_rx_queue(nbuf, 0);

		next = nbuf->next;

		/*
		 * Form the SG for msdu continued buffers
		 * QCN9000 has this support
		 */
		if (qdf_nbuf_is_rx_chfrag_cont(nbuf)) {
			nbuf = dp_rx_sg_create(soc, nbuf);
			next = nbuf->next;
			/*
			 * SG error handling is not done correctly,
			 * drop SG frames for now.
			 */
			dp_rx_nbuf_free(nbuf);
			dp_info_rl("scattered msdu dropped");
			nbuf = next;
			if (txrx_peer)
				dp_txrx_peer_unref_delete(txrx_ref_handle,
							  DP_MOD_ID_RX_ERR);
			continue;
		}

		if (wbm_err_info.wbm_err_src == HAL_RX_WBM_ERR_SRC_REO) {
			if (wbm_err_info.reo_psh_rsn
					== HAL_RX_WBM_REO_PSH_RSN_ERROR) {
				printk("[%s]<%d>DBG-lt  *** HAL_RX_WBM_ERR_SRC_REO && HAL_RX_WBM_REO_PSH_RSN_ERROR ***\n", __func__, __LINE__);
				DP_STATS_INC(soc,
					rx.err.reo_error
					[wbm_err_info.reo_err_code], 1);
				/* increment @pdev level */
				pool_id = wbm_err_info.pool_id;
				dp_pdev = dp_get_pdev_for_lmac_id(soc, pool_id);
				if (dp_pdev)
					DP_STATS_INC(dp_pdev, err.reo_error,
						     1);

				switch (wbm_err_info.reo_err_code) {
				/*
				 * Handling for packets which have NULL REO
				 * queue descriptor
				 */
				case HAL_REO_ERR_QUEUE_DESC_ADDR_0:
					printk("[%s]<%d>DBG-lt  case HAL_REO_ERR_QUEUE_DESC_ADDR_0 \n", __func__, __LINE__);
					pool_id = wbm_err_info.pool_id;
					dp_rx_null_q_desc_handle(soc, nbuf,
								 rx_tlv_hdr,
								 pool_id,
								 txrx_peer);
					break;
				/* TODO */
				/* Add per error code accounting */
				case HAL_REO_ERR_REGULAR_FRAME_2K_JUMP:
					printk("[%s]<%d>DBG-lt  HAL_REO_ERR_REGULAR_FRAME_2K_JUMP \n", __func__, __LINE__);
					if (txrx_peer)
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.jump_2k_err,
									  1);

					pool_id = wbm_err_info.pool_id;

					if (hal_rx_msdu_end_first_msdu_get(soc->hal_soc,
									   rx_tlv_hdr)) {
						tid =
						hal_rx_mpdu_start_tid_get(hal_soc, rx_tlv_hdr);
					}
					QDF_NBUF_CB_RX_PKT_LEN(nbuf) =
					hal_rx_msdu_start_msdu_len_get(
						soc->hal_soc, rx_tlv_hdr);
					nbuf->next = NULL;
					dp_2k_jump_handle(soc, nbuf,
							  rx_tlv_hdr,
							  peer_id, tid);
					break;
				case HAL_REO_ERR_REGULAR_FRAME_OOR:
					printk("[%s]<%d>DBG-lt  HAL_REO_ERR_REGULAR_FRAME_OOR \n", __func__, __LINE__);
					if (txrx_peer)
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.oor_err,
									  1);
					if (hal_rx_msdu_end_first_msdu_get(soc->hal_soc,
									   rx_tlv_hdr)) {
						tid =
							hal_rx_mpdu_start_tid_get(hal_soc, rx_tlv_hdr);
					}
					QDF_NBUF_CB_RX_PKT_LEN(nbuf) =
						hal_rx_msdu_start_msdu_len_get(
						soc->hal_soc, rx_tlv_hdr);
					nbuf->next = NULL;
					dp_rx_oor_handle(soc, nbuf,
							 peer_id,
							 rx_tlv_hdr);
					break;
				case HAL_REO_ERR_BAR_FRAME_2K_JUMP:
				case HAL_REO_ERR_BAR_FRAME_OOR:
					peer = dp_peer_get_tgt_peer_by_id(soc, peer_id, DP_MOD_ID_RX_ERR);
					printk("[%s]<%d>DBG-lt  HAL_REO_ERR_BAR_FRAME_OOR \n", __func__, __LINE__);
					if (peer) {
						dp_rx_err_handle_bar(soc, peer,
								     nbuf);
						dp_peer_unref_delete(peer, DP_MOD_ID_RX_ERR);
					}
					dp_rx_nbuf_free(nbuf);
					break;

				case HAL_REO_ERR_PN_CHECK_FAILED:
				case HAL_REO_ERR_PN_ERROR_HANDLING_FLAG_SET:
					printk("[%s]<%d>DBG-lt  HAL_REO_ERR_PN_ERROR_HANDLING_FLAG_SET \n", __func__, __LINE__);
					if (txrx_peer)
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.pn_err,
									  1);
					dp_rx_nbuf_free(nbuf);
					break;

				default:
					dp_info_rl("Got pkt with REO ERROR: %d",
						   wbm_err_info.reo_err_code);
					printk("[%s]<%d>DBG-lt  Got pkt with REO ERROR: %d \n", __func__, __LINE__, wbm_err_info.reo_err_code);
					dp_rx_nbuf_free(nbuf);
				}
			} else if (wbm_err_info.reo_psh_rsn
					== HAL_RX_WBM_REO_PSH_RSN_ROUTE) {
				dp_rx_err_route_hdl(soc, nbuf, txrx_peer,
						    rx_tlv_hdr,
						    HAL_RX_WBM_ERR_SRC_REO);
				printk("[%s]<%d>DBG-lt  HAL_RX_WBM_REO_PSH_RSN_ROUTE \n", __func__, __LINE__);
			} else {
				/* should not enter here */
				dp_rx_err_alert("invalid reo push reason %u",
						wbm_err_info.reo_psh_rsn);
				printk("[%s]<%d>DBG-lt  invalid reo push reason %u \n", __func__, __LINE__, wbm_err_info.reo_psh_rsn);
				dp_rx_nbuf_free(nbuf);
				qdf_assert_always(0);
			}
		} else if (wbm_err_info.wbm_err_src ==
					HAL_RX_WBM_ERR_SRC_RXDMA) {
			if (wbm_err_info.rxdma_psh_rsn
					== HAL_RX_WBM_RXDMA_PSH_RSN_ERROR) {
				printk("[%s]<%d>DBG-lt  HAL_RX_WBM_ERR_SRC_RXDMA && HAL_RX_WBM_RXDMA_PSH_RSN_ERROR \n", __func__, __LINE__);
				DP_STATS_INC(soc,
					rx.err.rxdma_error
					[wbm_err_info.rxdma_err_code], 1);
				/* increment @pdev level */
				pool_id = wbm_err_info.pool_id;
				dp_pdev = dp_get_pdev_for_lmac_id(soc, pool_id);
				if (dp_pdev)
					DP_STATS_INC(dp_pdev,
						     err.rxdma_error, 1);

				switch (wbm_err_info.rxdma_err_code) {
				case HAL_RXDMA_ERR_UNENCRYPTED:

				case HAL_RXDMA_ERR_WIFI_PARSE:
					printk("[%s]<%d>DBG-lt  HAL_RXDMA_ERR_WIFI_PARSE \n", __func__, __LINE__);
					if (txrx_peer)
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.rxdma_wifi_parse_err,
									  1);

					pool_id = wbm_err_info.pool_id;
					dp_rx_process_rxdma_err(soc, nbuf,
								rx_tlv_hdr,
								txrx_peer,
								wbm_err_info.
								rxdma_err_code,
								pool_id);
					break;

				case HAL_RXDMA_ERR_TKIP_MIC:
					printk("[%s]<%d>DBG-lt  HAL_RXDMA_ERR_TKIP_MIC \n", __func__, __LINE__);
					dp_rx_process_mic_error(soc, nbuf,
								rx_tlv_hdr,
								txrx_peer);
					if (txrx_peer)
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.mic_err,
									  1);
					break;

				case HAL_RXDMA_ERR_DECRYPT:
					printk("[%s]<%d>DBG-lt  HAL_RXDMA_ERR_DECRYPT \n", __func__, __LINE__);
					/* All the TKIP-MIC failures are treated as Decrypt Errors
					 * for QCN9224 Targets
					 */
					is_tkip_mic_err = hal_rx_msdu_end_is_tkip_mic_err(hal_soc, rx_tlv_hdr);

					if (is_tkip_mic_err && txrx_peer) {
						dp_rx_process_mic_error(soc, nbuf,
									rx_tlv_hdr,
									txrx_peer);
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.mic_err,
									  1);
						break;
					}

					if (txrx_peer) {
						DP_PEER_PER_PKT_STATS_INC(txrx_peer,
									  rx.err.decrypt_err,
									  1);
						dp_rx_nbuf_free(nbuf);
						break;
					}

					if (!dp_handle_rxdma_decrypt_err()) {
						dp_rx_nbuf_free(nbuf);
						break;
					}

					pool_id = wbm_err_info.pool_id;
					err_code = wbm_err_info.rxdma_err_code;
					tlv_hdr = rx_tlv_hdr;
					dp_rx_process_rxdma_err(soc, nbuf,
								tlv_hdr, NULL,
								err_code,
								pool_id);
					break;
				case HAL_RXDMA_MULTICAST_ECHO:
					printk("[%s]<%d>DBG-lt  HAL_RXDMA_MULTICAST_ECHO \n", __func__, __LINE__);
					if (txrx_peer)
						DP_PEER_PER_PKT_STATS_INC_PKT(txrx_peer,
									      rx.mec_drop, 1,
									      qdf_nbuf_len(nbuf));
					dp_rx_nbuf_free(nbuf);
					break;
				case HAL_RXDMA_UNAUTHORIZED_WDS:
					printk("[%s]<%d>DBG-lt  HAL_RXDMA_UNAUTHORIZED_WDS \n", __func__, __LINE__);
					pool_id = wbm_err_info.pool_id;
					err_code = wbm_err_info.rxdma_err_code;
					tlv_hdr = rx_tlv_hdr;
					dp_rx_process_rxdma_err(soc, nbuf,
								tlv_hdr,
								txrx_peer,
								err_code,
								pool_id);
					break;
				default:
					dp_rx_nbuf_free(nbuf);
					dp_err_rl("RXDMA error %d",
						  wbm_err_info.rxdma_err_code);
					printk("[%s]<%d>DBG-lt  RXDMA error %d \n", __func__, __LINE__, wbm_err_info.rxdma_err_code);
				}
			} else if (wbm_err_info.rxdma_psh_rsn
					== HAL_RX_WBM_RXDMA_PSH_RSN_ROUTE) {
				printk("[%s]<%d>DBG-lt  HAL_RX_WBM_RXDMA_PSH_RSN_ROUTE \n", __func__, __LINE__);
				dp_rx_err_route_hdl(soc, nbuf, txrx_peer,
						    rx_tlv_hdr,
						    HAL_RX_WBM_ERR_SRC_RXDMA);
			} else if (wbm_err_info.rxdma_psh_rsn
					== HAL_RX_WBM_RXDMA_PSH_RSN_FLUSH) {
				dp_rx_err_err("rxdma push reason %u",
						wbm_err_info.rxdma_psh_rsn);
				DP_STATS_INC(soc, rx.err.rx_flush_count, 1);
				dp_rx_nbuf_free(nbuf);
			} else {
				/* should not enter here */
				dp_rx_err_alert("invalid rxdma push reason %u",
						wbm_err_info.rxdma_psh_rsn);
				dp_rx_nbuf_free(nbuf);
				printk("[%s]<%d>DBG-lt  invalid rxdma push reason %u \n", __func__, __LINE__, wbm_err_info.rxdma_psh_rsn);
				qdf_assert_always(0);
			}
		} else {
			/* Should not come here */
			qdf_assert(0);
		}

		if (txrx_peer)
			dp_txrx_peer_unref_delete(txrx_ref_handle,
						  DP_MOD_ID_RX_ERR);

		nbuf = next;
	}
