/*
   Copyright (C) 1999-2022 Marc Huber (Marc.Huber@web.de)

   All rights reserved.

   Redistribution and use in source and binary  forms,  with or without
   modification, are permitted provided  that  the following conditions
   are met:

   1. Redistributions of source code  must  retain  the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions  and  the following disclaimer in
      the  documentation  and/or  other  materials  provided  with  the
      distribution.

   3. The end-user documentation  included with the redistribution,  if
      any, must include the following acknowledgment:

          This product includes software developed by Marc Huber
	  (Marc.Huber@web.de).

      Alternately,  this  acknowledgment  may  appear  in  the software
      itself, if and wherever such third-party acknowledgments normally
      appear.

   THIS SOFTWARE IS  PROVIDED  ``AS IS''  AND  ANY EXPRESSED OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL  ITS  AUTHOR  BE  LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED  TO,  PROCUREMENT OF  SUBSTITUTE  GOODS OR SERVICES;
   LOSS OF USE,  DATA,  OR PROFITS;  OR  BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY,  WHETHER IN CONTRACT,  STRICT
   LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)  ARISING IN
   ANY WAY OUT OF THE  USE  OF  THIS  SOFTWARE,  EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __PROTOCOL_RADIUS_H_
#define __PROTOCOL_RADIUS_H_

typedef struct {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    union {
	u_char authenticator[16];
	uint32_t token;
    };
} __attribute__((__packed__)) rad_pak_hdr;
#define RADIUS_HDR_SIZE sizeof(rad_pak_hdr)
#define RADIUS_DATA(A) (((u_char *)(A)) + RADIUS_HDR_SIZE)
#define RADIUS_DATA_LEN(A) (ntohs(((rad_pak_hdr *)A)->length) - RADIUS_HDR_SIZE)

// various #defines, mostly derived from RFC2856/RFC2866. 

#define RADIUS_CODE_ACCESS_REQUEST		1
#define RADIUS_CODE_ACCESS_ACCEPT		2
#define RADIUS_CODE_ACCESS_REJECT		3
#define RADIUS_CODE_ACCOUNTING_REQUEST		4
#define RADIUS_CODE_ACCOUNTING_RESPONSE		5
#define RADIUS_CODE_ACCESS_CHALLENGE		11
#define RADIUS_CODE_STATUS_SERVER		12
#define RADIUS_CODE_STATUS_CLIENT		13
#define RADIUS_CODE_PROTOCOL_ERROR		52

#define RADIUS_A_USER_NAME			1
#define RADIUS_A_USER_PASSWORD			2
#define RADIUS_A_CHAP_PASSWORD			3
#define RADIUS_A_NAS_IP_ADDRESS			4
#define RADIUS_A_NAS_PORT			5
#define RADIUS_A_SERVICE_TYPE			6
#define RADIUS_A_LOGIN_IP_HOST			14
#define RADIUS_A_LOGIN_SERVICE			15
#define RADIUS_A_LOGIN_TCP_PORT			16
#define RADIUS_A_REPLY_MESSAGE			18
#define RADIUS_A_STATE				24
#define RADIUS_A_CLASS				25
#define RADIUS_A_VENDOR_SPECIFIC		26
#define RADIUS_A_TERMINATION_ACTION		29
#define RADIUS_A_CALLED_STATION_ID		30
#define RADIUS_A_CALLING_STATION_ID		31
#define RADIUS_A_NAS_IDENTIFIER			32
#define RADIUS_A_CHAP_CHALLENGE			60
#define RADIUS_A_NAS_PORT_TYPE			61
#define RADIUS_A_MESSAGE_AUTHENTICATOR		80
#define RADIUS_A_NAS_PORT_ID			87
#define RADIUS_A_NAS_IPV6_ADDRESS		95

#define RADIUS_A_ERROR_CAUSE					101
#define RADIUS_V_ERROR_CAUSE_UNSUPPORTED_ATTRIBUTE		401
#define RADIUS_V_ERROR_CAUSE_MISSING_ATTRIBUTE			402
#define RADIUS_V_ERROR_CAUSE_NAS_IDENTIFICATION_MISMATCH	403
#define RADIUS_V_ERROR_CAUSE_INVALID_REQUEST			404
#define RADIUS_V_ERROR_CAUSE_UNSUPPORTED_SERVICE		405
#define RADIUS_V_ERROR_CAUSE_UNSUPPORTED_EXTENSIION		406
#define RADIUS_V_ERROR_CAUSE_INVALID_ATTRIBUTE_NAME		407
#define RADIUS_V_ERROR_CAUSE_ADMINISTRATIVELY_RROHIBITED	501
#define RADIUS_V_ERROR_CAUSE_SESSION_CONTEXT_NOT_FOUNF		503
#define RADIUS_V_ERROR_CAUSE_RESOURCES_UNAVAILABLE		506
#define RADIUS_V_ERROR_CAUSE_REQUEST_INITITED			507
#define RADIUS_V_ERROR_CAUSE_RESPONSE_TOO_BIG			601

#define RADIUS_A_ACCT_STATUS_TYPE			40
#define RADIUS_V_ACCT_STATUS_TYPE_START			1
#define RADIUS_V_ACCT_STATUS_TYPE_STOP			2
#define RADIUS_V_ACCT_STATUS_TYPE_INTERIM_UPDATE	3
#define RADIUS_V_ACCT_STATUS_TYPE_ACCOUNTING_ON		7
#define RADIUS_V_ACCT_STATUS_TYPE_ACCOUNTING_OFF	8

#define RADIUS_A_ACCT_DELAY_TIME	41
#define RADIUS_A_ACCT_INPUT_OCTETS	42
#define RADIUS_A_ACCT_OUTPUT_OCTETS	43
#define RADIUS_A_ACCT_SESSION_ID	44

#define RADIUS_A_ACCT_AUTHENTIC		45
#define RADIUS_V_ACCT_AUTHENTIC_RADIUS	1
#define RADIUS_V_ACCT_AUTHENTIC_LOCAL	2
#define RADIUS_V_ACCT_AUTHENTIC_REMOTE	3

#define RADIUS_A_ACCT_SESSION_TIME	46
#define RADIUS_A_ACCT_INPUT_PACKETS	47
#define RADIUS_A_ACCT_OUTPUT_PACKETS	48
#define RADIUS_A_ACCT_TERMINATE_CAUSE	49
#define RADIUS_A_ACCT_MULTI_SESSION_ID	50
#define RADIUS_A_ACCT_LINK_COUNT	51
#define RADIUS_A_ACCT_INTERIM_INTERVAL	85

#define RADIUS_VID_CISCO		"\0\0\0\011"	// 0x0009
#define RADIUS_A_CISCO_AVPAIR		1


#define ACSACL "#ACSACL#"
#endif				/* __PROTOCOL_RADIUS_H_ */
/*
 * vim:ts=4
 */
