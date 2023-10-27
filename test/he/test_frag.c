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
#include <unity.h>

#include "he.h"
#include "he_internal.h"
#include "test_defs.h"

// Unit under test
#include "frag.h"

// Direct includes for utility functions
#include "memory.h"

// Internal Mocks
#include "mock_conn_internal.h"

static he_conn_t conn = {0};

void setUp(void) {
}

void tearDown(void) {
  memset(&conn, 0, sizeof(he_conn_t));
  memset(empty_data, 0, sizeof(empty_data));
  call_counter = 0;
}

static he_return_code_t verify_internal_send_data_frag_message(he_conn_t *conn, uint8_t *message,
                                                               uint16_t length, int numCalls) {
  TEST_ASSERT_TRUE(length > sizeof(he_msg_data_frag_t));

  he_msg_data_frag_t *frag = (he_msg_data_frag_t *)message;

  TEST_ASSERT_EQUAL(HE_MSGID_DATA_WITH_FRAG, frag->msg_header.msgid);
  TEST_ASSERT_EQUAL(length - sizeof(he_msg_data_frag_t), ntohs(frag->length));
  TEST_ASSERT_EQUAL(conn->frag_next_id - 1, ntohs(frag->id));

  // Debug message
  char debug_message[1024] = {0};
  uint16_t off = ntohs(frag->offset);
  uint16_t offset = off & HE_FRAG_OFF_MASK;
  uint16_t mf = (off & HE_FRAG_MF_MASK) >> 13;
  snprintf(debug_message, sizeof(debug_message), "Fragment #%d, length: %d, MF: %d, offset: %d",
           numCalls, ntohs(frag->length), mf, offset * 8);
  TEST_MESSAGE(debug_message);

  TEST_ASSERT_EQUAL_MEMORY(empty_data + offset * 8, message + sizeof(he_msg_data_frag_t),
                           length - sizeof(he_msg_data_frag_t));

  return HE_SUCCESS;
}

void test_frag_and_send_message_null_pointers(void) {
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER,
                    he_internal_frag_and_send_message(NULL, empty_data, 1350, 1120));
  TEST_ASSERT_EQUAL(HE_ERR_NULL_POINTER,
                    he_internal_frag_and_send_message(&conn, NULL, 1350, 1120));
}

void test_frag_and_send_message(void) {
  // Fill random data to the test packet
  for(size_t i = 0; i < sizeof(empty_data); i++) {
    empty_data[i] = rand() % 256;
  }

  // First fragment
  he_internal_send_message_ExpectAndReturn(&conn, NULL, 512 + sizeof(he_msg_data_frag_t),
                                           HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();

  // Second fragment
  he_internal_send_message_ExpectAndReturn(&conn, NULL, 512 + sizeof(he_msg_data_frag_t),
                                           HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();

  // Last fragment
  he_internal_send_message_ExpectAndReturn(&conn, NULL, 326 + sizeof(he_msg_data_frag_t),
                                           HE_SUCCESS);
  he_internal_send_message_IgnoreArg_message();
  he_internal_send_message_AddCallback(verify_internal_send_data_frag_message);

  he_return_code_t ret = he_internal_frag_and_send_message(&conn, empty_data, 1350, 515);
  TEST_ASSERT_EQUAL(HE_SUCCESS, ret);
  TEST_ASSERT_EQUAL(1, conn.frag_next_id);
  TEST_ASSERT_EQUAL(sizeof(he_msg_hdr_t) + 6, sizeof(he_msg_data_frag_t));
}
