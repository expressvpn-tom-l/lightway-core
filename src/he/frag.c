/**
 * Lightway Core
 * Copyright (C) 2023 Express VPN International Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "he.h"
#include "he_internal.h"
#include "frag.h"
#include "conn_internal.h"

he_return_code_t he_internal_frag_and_send_message(he_conn_t *conn, uint8_t *packet,
                                                   uint16_t length, uint16_t frag_size) {
  if(!conn || !packet) {
    return HE_ERR_NULL_POINTER;
  }

  // Round the frag_size to the multiple of 8 bytes
  if(frag_size % 8 != 0) {
    frag_size = (frag_size / 8) * 8;
  }

  if(length <= frag_size) {
    // This should never happen, but we check it anyway.
    return HE_ERR_FAILED;
  }

  // Fragment identifier
  uint16_t frag_id = conn->frag_next_id++;

  uint16_t offset = 0;
  while(length > 0) {
    uint8_t bytes[HE_MAX_WIRE_MTU] = {0};

    // Allocate some space for the data message
    he_msg_data_frag_t *hdr = (he_msg_data_frag_t *)bytes;

    // Set message type
    hdr->msg_header.msgid = HE_MSGID_DATA_WITH_FRAG;

    // Set data length
    uint16_t frag_len = (length > frag_size) ? frag_size : length;
    hdr->length = htons(frag_len);

    // Set fragment id
    hdr->id = htons(frag_id);

    // Set fragment offset and mf flag
    uint8_t mf = (length > frag_size) ? 1 : 0;
    uint16_t off = (offset >> 3) | ((uint16_t)mf << 13);
    hdr->offset = htons(off);

    // Copy packet fragment to the buffer
    memcpy(bytes + sizeof(he_msg_data_frag_t), packet + offset, frag_len);

    // Send the message
    he_return_code_t ret =
        he_internal_send_message(conn, (uint8_t *)bytes, frag_len + sizeof(he_msg_data_frag_t));
    if(ret != HE_SUCCESS) {
      return ret;
    }

    length -= frag_len;
    offset += frag_len;
  };

  return HE_SUCCESS;
}
