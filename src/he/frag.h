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

/**
 * @file frag.h
 * @brief Internal header file for fragmentation support
 */

#ifndef FRAG_H
#define FRAG_H

#include "he_internal.h"

/**
 * @brief Fragment a packet and send it over the secured tunnel as multiple messages
 * @param conn A pointer to a valid connection
 * @param packet A pointer to the raw packet to be sent
 * @param length The length of the packet
 * @param frag_size Size of each fragment in bytes
 * @return HE_SUCCESS if the packet is fragmented and sent successfully
 */
he_return_code_t he_internal_frag_and_send_message(he_conn_t *conn, uint8_t *packet,
                                                   uint16_t length, uint16_t frag_size);

#endif  // FRAG_H
