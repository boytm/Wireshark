/* packet-rdp.c
 * Routines for Remote Desktop Protocol dissection
 * Copyright 2010, Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

//#ifdef HAVE_CONFIG_H
# include "config.h"
//#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include "packet-rdp.h"

#define TCP_PORT_RDP 3389

gint bytes = 0;
gint offset = 0;
gint rdp_offset = 0;
gint tpkt_offset = 0;
gint x224_offset = 0;
gint mcs_offset = 0;
gint ts_security_header_offset = 0;
gint ts_share_control_header_offset = 0;
gint ts_share_data_header_offset = 0;
gint ts_confirm_active_pdu_offset = 0;
gint ts_caps_set_offset = 0;

int proto_rdp = -1;
static int hf_rdp_rdp = -1;
static int hf_rdp_tpkt = -1;
static int hf_rdp_x224 = -1;
static int hf_rdp_mcs = -1;
static int hf_rdp_channel = -1;
static int hf_ts_security_header = -1;
static int hf_ts_client_info_pdu = -1;
static int hf_ts_share_control_header = -1;
static int hf_ts_share_data_header = -1;
static int hf_client_fastinput_event_pdu = -1;
static int hf_client_fastpath_input_events = -1;
static int hf_server_fastpath_output_pdu = -1;
static int hf_server_fastpath_outputs = -1;
static int hf_server_slowpath_graphics_update = -1;
static int hf_server_slowpath_pointer_update = -1;

static int hf_ts_confirm_active_pdu = -1;
static int hf_ts_confirm_active_pdu_shareid = -1;
static int hf_ts_confirm_active_pdu_originatorid = -1;
static int hf_ts_confirm_active_pdu_length_source_descriptor = -1;
static int hf_ts_confirm_active_pdu_length_combined_capabilities = -1;
static int hf_ts_confirm_active_pdu_source_descriptor = -1;
static int hf_ts_confirm_active_pdu_number_capabilities = -1;
static int hf_ts_confirm_active_pdu_pad2octets = -1;

static int hf_ts_demand_active_pdu = -1;
static int hf_ts_demand_active_pdu_sessionid = -1;

static int hf_mcs_connect_response_pdu = -1;
static int hf_mcs_connect_response_pdu_server_core_data = -1;
static int hf_mcs_connect_response_pdu_server_network_data = -1;
static int hf_mcs_connect_response_pdu_server_security_data = -1;
static int hf_mcs_connect_response_pdu_server_message_channel_data = -1;
static int hf_mcs_connect_response_pdu_server_multitransport_channel_data = -1;

static int hf_ts_server_security_encryption_method = -1;
static int hf_ts_server_security_encryption_level = -1;
static int hf_ts_server_public_key_modulus = -1;
static int hf_ts_server_public_key_exponent = -1;
static int hf_ts_server_proprietary_certificate_signature = -1;

static int hf_ts_input_event = -1;
static int hf_ts_output_update = -1;

static int hf_ts_capability_sets = -1;

static int hf_ts_caps_set = -1;
static int hf_ts_caps_set_capability_set_type = -1;
static int hf_ts_caps_set_length_capability = -1;
static int hf_ts_caps_set_capability_data = -1;

static int hf_ts_client_info_pdu_codepage = -1;
static int hf_ts_client_info_pdu_flags = -1;
static int hf_ts_client_info_pdu_domain_len = -1;
static int hf_ts_client_info_pdu_user_name_len = -1;
static int hf_ts_client_info_pdu_password_len = -1;
static int hf_ts_client_info_pdu_alternate_shell_len = -1;
static int hf_ts_client_info_pdu_working_dir_len = -1;
static int hf_ts_client_info_pdu_domain = -1;
static int hf_ts_client_info_pdu_user_name = -1;
static int hf_ts_client_info_pdu_password = -1;
static int hf_ts_client_info_pdu_alternate_shell = -1;
static int hf_ts_client_info_pdu_working_dir = -1;


static gint ett_rdp = -1;
static gint ett_ts_confirm_active_pdu = -1;
static gint ett_ts_capability_sets = -1;
static gint ett_ts_caps_set = -1;
static gint ett_mcs_connect_response_pdu = -1;
static gint ett_ts_server_secutiry_data = -1;
static gint ett_ts_input_events = -1;
static gint ett_ts_output_updates = -1;
static gint ett_ts_client_info_pdu = -1;

#define SEC_EXCHANGE_PKT			0x0001
#define SEC_ENCRYPT				0x0008
#define SEC_RESET_SEQNO				0x0010
#define SEC_IGNORE_SEQNO			0x0020
#define SEC_INFO_PKT				0x0040
#define SEC_LICENSE_PKT				0x0080
#define SEC_LICENSE_ENCRYPT_CS			0x0200
#define SEC_LICENSE_ENCRYPT_SC			0x0200
#define SEC_REDIRECTION_PKT			0x0400
#define SEC_SECURE_CHECKSUM			0x0800
#define SEC_FLAGSHI_VALID			0x8000

#define PDUTYPE_DEMAND_ACTIVE_PDU		0x1
#define PDUTYPE_CONFIRM_ACTIVE_PDU		0x3
#define PDUTYPE_DEACTIVATE_ALL_PDU		0x6
#define PDUTYPE_DATA_PDU			0x7
#define PDUTYPE_SERVER_REDIR_PKT		0xA

#define	PDUTYPE2_UPDATE				2
#define	PDUTYPE2_CONTROL			20
#define	PDUTYPE2_POINTER			27
#define	PDUTYPE2_INPUT				28
#define	PDUTYPE2_SYNCHRONIZE			31
#define	PDUTYPE2_REFRESH_RECT			33
#define	PDUTYPE2_PLAY_SOUND			34
#define	PDUTYPE2_SUPPRESS_OUTPUT		35
#define	PDUTYPE2_SHUTDOWN_REQUEST		36
#define	PDUTYPE2_SHUTDOWN_DENIED		37
#define	PDUTYPE2_SAVE_SESSION_INFO		38
#define	PDUTYPE2_FONTLIST			39
#define	PDUTYPE2_FONTMAP			40
#define	PDUTYPE2_SET_KEYBOARD_INDICATORS	41
#define	PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST	43
#define	PDUTYPE2_BITMAPCACHE_ERROR_PDU		44
#define	PDUTYPE2_SET_KEYBOARD_IME_STATUS	45
#define	PDUTYPE2_OFFSCRCACHE_ERROR_PDU		46
#define	PDUTYPE2_SET_ERROR_INFO_PDU		47
#define	PDUTYPE2_DRAWNINEGRID_ERROR_PDU		48
#define	PDUTYPE2_DRAWGDIPLUS_ERROR_PDU		49
#define	PDUTYPE2_ARC_STATUS_PDU			50
#define	PDUTYPE2_STATUS_INFO_PDU		54
#define	PDUTYPE2_MONITOR_LAYOUT_PDU		55

#define CAPSET_TYPE_GENERAL                     0x0001
#define CAPSET_TYPE_BITMAP                      0x0002
#define CAPSET_TYPE_ORDER                       0x0003
#define CAPSET_TYPE_BITMAPCACHE                 0x0004
#define CAPSET_TYPE_CONTROL                     0x0005
#define CAPSET_TYPE_ACTIVATION                  0x0007
#define CAPSET_TYPE_POINTER                     0x0008
#define CAPSET_TYPE_SHARE                       0x0009
#define CAPSET_TYPE_COLORCACHE                  0x000A
#define CAPSET_TYPE_SOUND                       0x000C
#define CAPSET_TYPE_INPUT                       0x000D
#define CAPSET_TYPE_FONT                        0x000E
#define CAPSET_TYPE_BRUSH                       0x000F
#define CAPSET_TYPE_GLYPHCACHE                  0x0010
#define CAPSET_TYPE_OFFSCREENCACHE              0x0011
#define CAPSET_TYPE_BITMAPCACHE_HOSTSUPPORT     0x0012
#define CAPSET_TYPE_BITMAPCACHE_REV2            0x0013
#define CAPSET_TYPE_VIRTUALCHANNEL              0x0014
#define CAPSET_TYPE_DRAWNINEGRIDCACHE           0x0015
#define CAPSET_TYPE_DRAWGDIPLUS                 0x0016
#define CAPSET_TYPE_RAIL                        0x0017
#define CAPSET_TYPE_WINDOW                      0x0018
#define CAPSET_TYPE_COMPDESK                    0x0019
#define CAPSET_TYPE_MULTIFRAGMENTUPDATE         0x001A
#define CAPSET_TYPE_LARGE_POINTER               0x001B
#define CAPSET_TYPE_SURFACE_COMMANDS            0x001C
#define CAPSET_TYPE_BITMAP_CODECS               0x001D

#define MCS_ERECT_DOMAIN_REQUEST		0x01
#define MCS_DISCONNECT_PROVIDER_ULTIMATUM	0x08
#define MCS_ATTACH_USER_REQUEST			0x0A
#define MCS_ATTACH_USER_CONFIRM			0x0B
#define MCS_CHANNEL_JOIN_REQUEST		0x0E
#define MCS_CHANNEL_JOIN_CONFIRM		0x0F
#define MCS_SEND_DATA_REQUEST			0x19
#define MCS_SEND_DATA_INDICATION		0x1A
#define MCS_CONNECT_INITIAL			0x65
#define MCS_CONNECT_RESPONSE			0x66

#define X224_CONNECTION_REQUEST			0xE
#define X224_CONNECTION_CONFIRM			0xD
#define X224_DISCONNECT_REQUEST			0x8
#define X224_DISCONNECT_CONFIRM			0xC
#define X224_DATA				0xF

#define PROTOCOL_RDP            0x00000000
#define PROTOCOL_SSL            0x00000001
#define PROTOCOL_HYBRID         0x00000002
#define PROTOCOL_HYBRID_EX      0x00000008

#define SSL_REQUIRED_BY_SERVER 0x00000001 
#define SSL_NOT_ALLOWED_BY_SERVER 0x00000002 
#define SSL_CERT_NOT_ON_SERVER 0x00000003 
#define INCONSISTENT_FLAGS 0x00000004 
#define HYBRID_REQUIRED_BY_SERVER 0x00000005 
#define SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER 0x00000006

#define TYPE_RDP_NEG_REQ 0x01
#define TYPE_RDP_NEG_RSP 0x02
#define TYPE_RDP_NEG_FAILURE 0x03

#define BER_TAG_BOOLEAN                1
#define BER_TAG_INTEGER                2
#define BER_TAG_OCTET_STRING           4
#define BER_TAG_RESULT                 10
#define MCS_TAG_DOMAIN_PARAMS          0x30

#define ENCRYPTION_METHOD_NONE 0x00000000 
#define ENCRYPTION_METHOD_40BIT 0x00000001 
#define ENCRYPTION_METHOD_128BIT 0x00000002 
#define ENCRYPTION_METHOD_56BIT 0x00000008 
#define ENCRYPTION_METHOD_FIPS 0x00000010 

#define ENCRYPTION_LEVEL_NONE  0x00000000 
#define ENCRYPTION_LEVEL_LOW  0x00000001 
#define ENCRYPTION_LEVEL_CLIENT_COMPATIBLE  0x00000002 
#define ENCRYPTION_LEVEL_HIGH  0x00000003 
#define ENCRYPTION_LEVEL_FIPS  0x00000004 

#define CERT_CHAIN_VERSION_1 0x00000001 
#define CERT_CHAIN_VERSION_2 0x00000002 

#define SIGNATURE_ALG_RSA 0x00000001
#define KEY_EXCHANGE_ALG_RSA 0x00000001

#define BB_RSA_KEY_BLOB 0x0006
#define BB_RSA_SIGNATURE_BLOB 0x0008

#define FASTPATH_INPUT_ACTION_FASTPATH 0x0
#define FASTPATH_INPUT_ACTION_X224 0x3 

#define FASTPATH_INPUT_SECURE_CHECKSUM 0x1 
#define FASTPATH_INPUT_ENCRYPTED 0x2 

#define FASTPATH_UPDATETYPE_ORDERS 0x0 
#define FASTPATH_UPDATETYPE_BITMAP 0x1 
#define FASTPATH_UPDATETYPE_PALETTE 0x2 
#define FASTPATH_UPDATETYPE_SYNCHRONIZE 0x3 
#define FASTPATH_UPDATETYPE_SURFCMDS 0x4 
#define FASTPATH_UPDATETYPE_PTR_NULL 0x5 
#define FASTPATH_UPDATETYPE_PTR_DEFAULT 0x6 
#define FASTPATH_UPDATETYPE_PTR_POSITION 0x8 
#define FASTPATH_UPDATETYPE_COLOR 0x9 
#define FASTPATH_UPDATETYPE_CACHED 0xA 
#define FASTPATH_UPDATETYPE_POINTER 0xB 

#define FASTPATH_FRAGMENT_SINGLE 0x0 
#define FASTPATH_FRAGMENT_LAST 0x1 
#define FASTPATH_FRAGMENT_FIRST 0x2 
#define FASTPATH_FRAGMENT_NEXT 0x3 

#define FASTPATH_OUTPUT_COMPRESSION_USED 0x2 

#define CompressionTypeMask 0x0F 
#define PACKET_COMPRESSED 0x20 
#define PACKET_AT_FRONT 0x40 
#define PACKET_FLUSHED 0x80 

#define PACKET_COMPR_TYPE_8K 0x0 
#define PACKET_COMPR_TYPE_64K 0x1 
#define PACKET_COMPR_TYPE_RDP6 0x2 
#define PACKET_COMPR_TYPE_RDP61 0x3 

static const value_string protocol_types[] = {
    { PROTOCOL_RDP, "RDP" },
    { PROTOCOL_SSL, "TLS" },
    { PROTOCOL_HYBRID, "CredSSP" },
    { PROTOCOL_HYBRID_EX, "CredSSP coupled with the Early User Authorization Result PDU" },
	{ 0x0,	NULL }
};

static const value_string nego_failure_types[] = {
    { SSL_REQUIRED_BY_SERVER, "0x00000001 " },
    { SSL_NOT_ALLOWED_BY_SERVER, "0x00000002 " },
    { SSL_CERT_NOT_ON_SERVER, "0x00000003 " },
    { INCONSISTENT_FLAGS, "0x00000004 " },
    { HYBRID_REQUIRED_BY_SERVER, "0x00000005 " },
    { SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER, "0x00000006" },
	{ 0x0,	NULL }
};

static const value_string nego_types[] = {
    { TYPE_RDP_NEG_REQ, "Negotiation Request" },
    { TYPE_RDP_NEG_RSP, "Negotiation Response" },
    { TYPE_RDP_NEG_FAILURE, "Negotiation Failure" },

	{ 0x0,	NULL }
};

static const value_string capability_set_types[] = {
	{ CAPSET_TYPE_GENERAL,			"General" },
	{ CAPSET_TYPE_BITMAP,			"Bitmap" },
	{ CAPSET_TYPE_ORDER,			"Order" },
	{ CAPSET_TYPE_BITMAPCACHE,		"Bitmap Cache Revision 1" },
	{ CAPSET_TYPE_CONTROL,			"Control" },
	{ CAPSET_TYPE_ACTIVATION,		"Window Activation" },
	{ CAPSET_TYPE_POINTER,			"Pointer" },
	{ CAPSET_TYPE_SHARE,			"Share" },
	{ CAPSET_TYPE_COLORCACHE,		"Color Table Cache" },
	{ CAPSET_TYPE_SOUND,			"Sound" },
	{ CAPSET_TYPE_INPUT,			"Input" },
	{ CAPSET_TYPE_FONT,			"Font" },
	{ CAPSET_TYPE_BRUSH,			"Brush" },
	{ CAPSET_TYPE_GLYPHCACHE,		"Glyph" },
	{ CAPSET_TYPE_OFFSCREENCACHE,		"Offscreen" },
	{ CAPSET_TYPE_BITMAPCACHE_HOSTSUPPORT,	"Bitmap Cache Host Support" },
	{ CAPSET_TYPE_BITMAPCACHE_REV2,		"Bitmap Cache Revison 2" },
	{ CAPSET_TYPE_VIRTUALCHANNEL,		"Virtual Channel" },
	{ CAPSET_TYPE_DRAWNINEGRIDCACHE,	"DrawNineGrid Cache" },
	{ CAPSET_TYPE_DRAWGDIPLUS,		"Draw GDI+ Cache" },
	{ CAPSET_TYPE_RAIL,			"Remote Programs" },
	{ CAPSET_TYPE_WINDOW,			"Window List" },
	{ CAPSET_TYPE_COMPDESK,			"Desktop Composition Extension" },
	{ CAPSET_TYPE_MULTIFRAGMENTUPDATE,	"Multifragment Update" },
	{ CAPSET_TYPE_LARGE_POINTER,		"Large Pointer" },
	{ CAPSET_TYPE_SURFACE_COMMANDS,		"Surface Commands" },
	{ CAPSET_TYPE_BITMAP_CODECS,		"Bitmap Codecs" },
	{ 0x0,	NULL }
};

static const value_string pdu_types[] = {
	{ PDUTYPE_DEMAND_ACTIVE_PDU,		"Demand Active" },
	{ PDUTYPE_CONFIRM_ACTIVE_PDU,		"Confirm Active" },
	{ PDUTYPE_DEACTIVATE_ALL_PDU,		"Deactivate All" },
	{ PDUTYPE_DATA_PDU,			"Data" },
	{ PDUTYPE_SERVER_REDIR_PKT,		"Server Redirection Packet" },
	{ 0x0,	NULL }
};

static const value_string pdu2_types[] = {
	{ PDUTYPE2_UPDATE,			"Update" },
	{ PDUTYPE2_CONTROL,			"Control" },
	{ PDUTYPE2_POINTER,			"Pointer" },
	{ PDUTYPE2_INPUT,			"Input" },
	{ PDUTYPE2_SYNCHRONIZE,			"Synchronize" },
	{ PDUTYPE2_REFRESH_RECT,		"Refresh Rect" },
	{ PDUTYPE2_PLAY_SOUND,			"Play Sound" },
	{ PDUTYPE2_SUPPRESS_OUTPUT,		"Suppress Output" },
	{ PDUTYPE2_SHUTDOWN_REQUEST,		"Shutdown Request" },
	{ PDUTYPE2_SHUTDOWN_DENIED,		"Shutdown Denied" },
	{ PDUTYPE2_SAVE_SESSION_INFO,		"Save Session Info" },
	{ PDUTYPE2_FONTLIST,			"Font List" },
	{ PDUTYPE2_FONTMAP,			"Font Map" },
	{ PDUTYPE2_SET_KEYBOARD_INDICATORS,	"Set Keyboard Indicator" },
	{ PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST,	"Bitmap Cache Persistent List" },
	{ PDUTYPE2_BITMAPCACHE_ERROR_PDU,	"Bitmap Cache Error" },
	{ PDUTYPE2_SET_KEYBOARD_IME_STATUS,	"Set Keyboard IME Status" },
	{ PDUTYPE2_OFFSCRCACHE_ERROR_PDU,	"Offscreen Cache Error" },
	{ PDUTYPE2_SET_ERROR_INFO_PDU,		"Set Error Info" },
	{ PDUTYPE2_DRAWNINEGRID_ERROR_PDU,	"Draw Nine Grid Error" },
	{ PDUTYPE2_DRAWGDIPLUS_ERROR_PDU,	"Draw GDI+ Error" },
	{ PDUTYPE2_ARC_STATUS_PDU,		"Arc Status" },
	{ PDUTYPE2_STATUS_INFO_PDU,		"Status Info" },
	{ PDUTYPE2_MONITOR_LAYOUT_PDU,		"Monitor Layout" },
	{ 0x0,	NULL }
};

static const value_string t125_mcs_tpdu_types[] = {
	{ MCS_ERECT_DOMAIN_REQUEST,		"Erect Domain Request" },
	{ MCS_DISCONNECT_PROVIDER_ULTIMATUM,	"Disconnect Provider Ultimatum" },
	{ MCS_ATTACH_USER_REQUEST,		"Attach User Request" },
	{ MCS_ATTACH_USER_CONFIRM,		"Attach User Confirm" },
	{ MCS_CHANNEL_JOIN_REQUEST,		"Channel Join Request" },
	{ MCS_CHANNEL_JOIN_CONFIRM,		"Channel Join Confirm" },
	{ MCS_SEND_DATA_REQUEST,		"Send Data Request" },
	{ MCS_SEND_DATA_INDICATION,		"Send Data Indication" },
	{ MCS_CONNECT_INITIAL,			"Connect Initial" },
	{ MCS_CONNECT_RESPONSE,			"Connect Response" },
	{ 0x0,	NULL }
};

static const value_string x224_tpdu_types[] = {
	{ X224_CONNECTION_REQUEST,		"Connection Request" },
	{ X224_CONNECTION_CONFIRM,		"Connection Confirm" },
	{ X224_DISCONNECT_REQUEST,		"Disconnect Request" },
	{ X224_DISCONNECT_CONFIRM,		"Disconnect Confirm" },
	{ X224_DATA,				"Data" },
	{ 0x0,	NULL }
};

static const value_string fast_path_input_event_security [] = {
	{ FASTPATH_INPUT_ENCRYPTED,		"Encrypted" },
	{ FASTPATH_INPUT_ENCRYPTED | FASTPATH_INPUT_SECURE_CHECKSUM,		"Encrypted with checksum" },
	{ 0x0,	NULL }
};

static const value_string fast_path_output_update_types [] = {
    { FASTPATH_UPDATETYPE_ORDERS, "Orders Update" },  
    { FASTPATH_UPDATETYPE_BITMAP, "Bitmap Update" },  
    { FASTPATH_UPDATETYPE_PALETTE, "Palette Update" },  
    { FASTPATH_UPDATETYPE_SYNCHRONIZE, "Synchronize Update" },  
    { FASTPATH_UPDATETYPE_SURFCMDS, "Surface Commands Update" }, 
    { FASTPATH_UPDATETYPE_PTR_NULL, "System Pointer Hidden Update" },  
    { FASTPATH_UPDATETYPE_PTR_DEFAULT, "System Pointer Default Update" },  
    { FASTPATH_UPDATETYPE_PTR_POSITION, "Pointer Position Update" },  
    { FASTPATH_UPDATETYPE_COLOR, "Color Pointer Update" },  
    { FASTPATH_UPDATETYPE_CACHED, "Cached Pointer Update" },
    { FASTPATH_UPDATETYPE_POINTER, "New Pointer Update" },
    { 0x0,	NULL }
};

static const value_string fast_path_fragment_types [] = {
    { FASTPATH_FRAGMENT_SINGLE, "Single" }, 
    { FASTPATH_FRAGMENT_LAST, "Last" }, 
    { FASTPATH_FRAGMENT_FIRST, "First" }, 
    { FASTPATH_FRAGMENT_NEXT, "Next" }, 
    { 0x0,	NULL }
};

static const value_string rdp_compress_types [] = {
    { PACKET_COMPR_TYPE_8K, "RDP 4.0 bulk compression" },
    { PACKET_COMPR_TYPE_64K, "RDP 5.0 bulk compression" },
    { PACKET_COMPR_TYPE_RDP6, "RDP 6.0 bulk compression" },
    { PACKET_COMPR_TYPE_RDP61, "RDP 6.1 bulk compression" },
    { 0x0,	NULL }
};


void proto_reg_handoff_rdp(void);
void dissect_ts_caps_set(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree);
void dissect_ts_confirm_active_pdu(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree);
void dissect_ts_client_info_packet(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree);
void dissect_ts_share_control_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree);
void dissect_ts_share_data_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree);
gint32 dissect_ts_security_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree);

#define RDP_SECURITY_STANDARD 1024
#define RDP_SECURITY_SSL 1
#define RDP_SECURITY_HYBRID 2
#define RDP_SECURITY_ENHANCED 0x8000
typedef struct _rdp_conv_info_t
{
    guint32 rdp_security;
    guint32 have_server_license_error_pdu; // frame number. After Server License Error PDU, security header become optional
    guint16 server_port;
    //guint32 encryption_method;
    //guint32 encryption_level;
    //guint32 server_public_key_len;
    //guint32 exponent;
    //char[256] server_modulus;
    //char[256] client_modulus;

} rdp_conv_info_t;

inline rdp_conv_info_t* conversation_data(packet_info *pinfo)
{
    conversation_t *conversation;
    rdp_conv_info_t *rdp_info;

    conversation = find_or_create_conversation(pinfo);

    rdp_info = (rdp_conv_info_t *)conversation_get_proto_data(conversation, proto_rdp);
    if (!rdp_info) {
        /* No.  Attach that information to the conversation, and add
         *                 * it to the list of information structures.
         *                                 */
        rdp_info = se_new(rdp_conv_info_t);

        memset(rdp_info, 0, sizeof(*rdp_info));

        conversation_add_proto_data(conversation, proto_rdp, rdp_info);
    }

    return rdp_info;
}

void
dissect_ts_caps_set(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint16 capabilitySetType;
	guint16 lengthCapability;

	if (tree)
	{
		proto_item *ti;
		proto_tree *ts_caps_set_tree;

		ts_caps_set_offset = offset;
		capabilitySetType = tvb_get_letohs(tvb, offset);
		lengthCapability = tvb_get_letohs(tvb, offset + 2);

		ti = proto_tree_add_item(tree, hf_ts_caps_set, tvb, ts_caps_set_offset, lengthCapability, TRUE);
		ts_caps_set_tree = proto_item_add_subtree(ti, ett_ts_caps_set);

		proto_item_set_text(ti, "%s Capability Set", val_to_str(capabilitySetType, capability_set_types, "Unknown %d Capability Set"));
		proto_item_append_text(ti, ", Length = %d", lengthCapability - 4);

		proto_tree_add_item(ts_caps_set_tree, hf_ts_caps_set_capability_set_type, tvb, offset, 2, TRUE);
		proto_tree_add_item(ts_caps_set_tree, hf_ts_caps_set_length_capability, tvb, offset + 2, 2, TRUE);
		proto_tree_add_item(ts_caps_set_tree, hf_ts_caps_set_capability_data, tvb, offset + 4, lengthCapability - 4, TRUE);
		offset += lengthCapability;
	}
}

void
dissect_ts_confirm_active_pdu(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint32 shareId;
	guint16 originatorId;
	guint16 lengthSourceDescriptor;
	guint16 lengthCombinedCapabilities;
	guint16 numberCapabilities;

	if (tree)
	{
		int i;
		proto_item *ti;
		proto_tree *ts_confirm_active_pdu_tree;
		proto_tree *ts_capability_sets_tree;

		ts_confirm_active_pdu_offset = offset;
		shareId = tvb_get_letohl(tvb, offset);
		originatorId = tvb_get_letohs(tvb, offset + 4);
		lengthSourceDescriptor = tvb_get_letohs(tvb, offset + 6);
		lengthCombinedCapabilities = tvb_get_letohs(tvb, offset + 8);
		numberCapabilities = tvb_get_letohs(tvb, offset + 10 + lengthSourceDescriptor);

		ti = proto_tree_add_item(tree, hf_ts_confirm_active_pdu, tvb, ts_confirm_active_pdu_offset, -1, TRUE);
		ts_confirm_active_pdu_tree = proto_item_add_subtree(ti, ett_ts_confirm_active_pdu);

		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_shareid, tvb, offset, 4, TRUE);
		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_originatorid, tvb, offset + 4, 2, TRUE);
		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_length_source_descriptor, tvb, offset + 6, 2, TRUE);
		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_length_combined_capabilities, tvb, offset + 8, 2, TRUE);
		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_source_descriptor, tvb, offset + 10, lengthSourceDescriptor, TRUE);
		offset += (10 + lengthSourceDescriptor);

		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_number_capabilities, tvb, offset, 2, TRUE);
		proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_confirm_active_pdu_pad2octets, tvb, offset + 2, 2, TRUE);
		offset += 4;

		ti = proto_tree_add_item(ts_confirm_active_pdu_tree, hf_ts_capability_sets, tvb, offset, lengthCombinedCapabilities - 4, TRUE);
		ts_capability_sets_tree = proto_item_add_subtree(ti, ett_ts_capability_sets);

		for (i = 0; i < numberCapabilities; i++)
			dissect_ts_caps_set(tvb, pinfo, ts_capability_sets_tree);
	}
}
// ENC_NA
void
dissect_ts_demand_active_pdu(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint32 shareId;
	guint16 lengthSourceDescriptor;
	guint16 lengthCombinedCapabilities;
	guint16 numberCapabilities;

    guint32 ts_demand_active_pdu_offset;

	if (tree)
	{
		int i;
		proto_item *ti;
		proto_tree *ts_demand_active_pdu_tree;
		proto_tree *ts_capability_sets_tree;

		ts_demand_active_pdu_offset = offset;
		shareId = tvb_get_letohl(tvb, offset);
        // compare to Confirm Active PDU, lack originatorId
		lengthSourceDescriptor = tvb_get_letohs(tvb, offset + 4);
		lengthCombinedCapabilities = tvb_get_letohs(tvb, offset + 6);
		numberCapabilities = tvb_get_letohs(tvb, offset + 8 + lengthSourceDescriptor);

		ti = proto_tree_add_item(tree, hf_ts_demand_active_pdu, tvb, ts_demand_active_pdu_offset, -1, TRUE);
		ts_demand_active_pdu_tree = proto_item_add_subtree(ti, ett_ts_confirm_active_pdu);

		proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_confirm_active_pdu_shareid, tvb, offset, 4, TRUE);
		proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_confirm_active_pdu_length_source_descriptor, tvb, offset + 4, 2, TRUE);
		proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_confirm_active_pdu_length_combined_capabilities, tvb, offset + 6, 2, TRUE);
		proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_confirm_active_pdu_source_descriptor, tvb, offset + 8, lengthSourceDescriptor, TRUE);
		offset += (8 + lengthSourceDescriptor);

		proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_confirm_active_pdu_number_capabilities, tvb, offset, 2, TRUE);
		proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_confirm_active_pdu_pad2octets, tvb, offset + 2, 2, TRUE);
		offset += 4;

		ti = proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_capability_sets, tvb, offset, lengthCombinedCapabilities - 4, TRUE);
		ts_capability_sets_tree = proto_item_add_subtree(ti, ett_ts_capability_sets);

		for (i = 0; i < numberCapabilities; i++)
			dissect_ts_caps_set(tvb, pinfo, ts_capability_sets_tree);

        proto_tree_add_item(ts_demand_active_pdu_tree, hf_ts_demand_active_pdu_sessionid, tvb, offset, 4, TRUE);
	}
}

void
dissect_ts_client_info_packet(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint32 codePage;
	guint32 flags;
	guint16 cbDomain;
	guint16 cbUserName;
	guint16 cbPassword;
	guint16 cbAlternateShell;
	guint16 cbWorkingDir;

	if (tree && tvb_length_remaining(tvb, offset) >= 18)
	{
		codePage = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(tree, hf_ts_client_info_pdu_codepage, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

		flags = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(tree, hf_ts_client_info_pdu_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

		cbDomain = tvb_get_letohs(tvb, offset) + 2;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_domain_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

		cbUserName = tvb_get_letohs(tvb, offset) + 2;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_user_name_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

		cbPassword = tvb_get_letohs(tvb, offset) + 2;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_password_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

		cbAlternateShell = tvb_get_letohs(tvb, offset) + 2;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_alternate_shell_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

		cbWorkingDir = tvb_get_letohs(tvb, offset) + 2;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_working_dir_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;


        proto_tree_add_item(tree, hf_ts_client_info_pdu_domain, tvb, offset, cbDomain, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += cbDomain;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_user_name, tvb, offset, cbUserName, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += cbUserName;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_password, tvb, offset, cbPassword, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += cbPassword;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_alternate_shell, tvb, offset, cbAlternateShell, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += cbAlternateShell;
        proto_tree_add_item(tree, hf_ts_client_info_pdu_working_dir, tvb, offset, cbWorkingDir, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
        offset += cbWorkingDir;

        if (tvb_length_remaining(tvb, offset) > 0)
        {
            // Extended Info Packet
        }
	}
}

#define UPDATETYPE_ORDERS 0x0000 
#define UPDATETYPE_BITMAP 0x0001 
#define UPDATETYPE_PALETTE 0x0002 
#define UPDATETYPE_SYNCHRONIZE 0x0003 

static const value_string slow_path_graphics_update_types[] = {
    { UPDATETYPE_ORDERS, "Orders Update" },
    { UPDATETYPE_BITMAP, " Bitmap Graphics Update" },
    { UPDATETYPE_PALETTE, "Palette Update" },
    { UPDATETYPE_SYNCHRONIZE, "Synchronize Update"},
    { 0x0,	NULL }
};

#define TS_PTRMSGTYPE_SYSTEM 0x0001 
#define TS_PTRMSGTYPE_POSITION 0x0003 
#define TS_PTRMSGTYPE_COLOR 0x0006 
#define TS_PTRMSGTYPE_CACHED 0x0007 
#define TS_PTRMSGTYPE_POINTER 0x0008 

static const value_string slow_path_pointer_update_types[] = {
    { TS_PTRMSGTYPE_SYSTEM, "System Pointer Update" },
    { TS_PTRMSGTYPE_POSITION, "Pointer Position Update" },
    { TS_PTRMSGTYPE_COLOR, "Color Pointer Update" },
    { TS_PTRMSGTYPE_CACHED, "Cached Pointer Update" },
    { TS_PTRMSGTYPE_POINTER, "New Pointer Update" },
    { 0x0,	NULL }
};

void
dissect_ts_server_graphics_update(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    proto_item *ti;
    guint16 message_type = tvb_get_letohs(tvb, offset);

    ti = proto_tree_add_item(tree, hf_server_slowpath_graphics_update, tvb, offset, -1, FALSE);
    proto_item_set_text(ti, "Server Graphics Update PDU: %s", val_to_str(message_type, slow_path_graphics_update_types, "Unknown %d"));

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, slow_path_graphics_update_types, "Unknown %d"));
}
void
dissect_ts_server_pointer_update(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    proto_item *ti;
    guint16 message_type = tvb_get_letohs(tvb, offset);

    ti = proto_tree_add_item(tree, hf_server_slowpath_pointer_update, tvb, offset, -1, FALSE);
    proto_item_set_text(ti, "Server Pointer Update PDU : %s", val_to_str(message_type, slow_path_pointer_update_types, "Unknown %d"));

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, slow_path_pointer_update_types, "Unknown %d"));
}
void
dissect_ts_share_data_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint32 shareId;
	guint8 streamId;
	guint16 uncompressedLength;
	guint8 pduType2;
    guint8 compressed_type;
    guint16 compressed_length;

    guint8 detail_compression[128] = {'\0'};

	if (tree)
	{
		bytes = tvb_length_remaining(tvb, 0);

		if (bytes >= 4)
		{
			proto_item *ti;
			ts_share_data_header_offset = offset;
			shareId = tvb_get_letohl(tvb, offset);
			streamId = tvb_get_guint8(tvb, offset + 5);
			uncompressedLength = tvb_get_letohs(tvb, offset + 6);
			pduType2 = tvb_get_guint8(tvb, offset + 8);
            compressed_type = tvb_get_guint8(tvb, offset +9);
            compressed_length = tvb_get_letohs(tvb, offset + 10);
			offset += 12;

            if(compressed_type & PACKET_COMPRESSED)
            {
                g_snprintf(detail_compression, sizeof(detail_compression), ", %s, Compressed Length %d", 
                        val_to_str(compressed_type & CompressionTypeMask, rdp_compress_types, "Unknown %d"), compressed_length);
            }

			ti = proto_tree_add_item(tree, hf_ts_share_data_header, tvb, ts_share_data_header_offset, offset - ts_share_data_header_offset, FALSE);
			proto_item_set_text(ti, "TS_SHARE_DATA_HEADER: %s, Uncompressed Length %d %s", val_to_str(pduType2, pdu2_types, "Unknown %d"), 
                    uncompressedLength,
                    detail_compression);

			col_clear(pinfo->cinfo, COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s PDU", val_to_str(pduType2, pdu2_types, "Data %d PDU"));

            switch (pduType2)
            {
                case PDUTYPE2_UPDATE:
                    dissect_ts_server_graphics_update(tvb, pinfo, tree);
                    break;
                case PDUTYPE2_POINTER:
                    dissect_ts_server_pointer_update(tvb, pinfo, tree);
                    break;
            }
		}
	}
}

void
dissect_ts_share_control_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree) // 从Demand Active PDU开始有此header
{
	guint16 pduType;
	guint16 PDUSource;
	guint16 totalLength;

	if (tree)
	{
		bytes = tvb_length_remaining(tvb, offset);
		totalLength = tvb_get_letohs(tvb, offset);

		if (bytes >= 4)
		{
			proto_item *ti;
			ts_share_control_header_offset = offset;
			pduType = tvb_get_letohs(tvb, offset + 2) & 0xF;
			PDUSource = tvb_get_letohs(tvb, offset + 4);

			if (totalLength == 128)
				return;

			offset += 6;
			ti = proto_tree_add_item(tree, hf_ts_share_control_header, tvb, ts_share_control_header_offset, offset - ts_share_control_header_offset, FALSE);
			proto_item_set_text(ti, "TS_SHARE_CONTROL_HEADER: %s, length %d", val_to_str(pduType, pdu_types, "Unknown %d"), totalLength);

			switch (pduType)
			{
				case PDUTYPE_DEMAND_ACTIVE_PDU:
					col_set_str(pinfo->cinfo, COL_INFO, "Demand Active PDU");
					dissect_ts_demand_active_pdu(tvb, pinfo, tree);
					break;

				case PDUTYPE_CONFIRM_ACTIVE_PDU:
					col_set_str(pinfo->cinfo, COL_INFO, "Confirm Active PDU");
					dissect_ts_confirm_active_pdu(tvb, pinfo, tree);
					break;

                case PDUTYPE_DEACTIVATE_ALL_PDU:
                case PDUTYPE_SERVER_REDIR_PKT:
					col_set_str(pinfo->cinfo, COL_INFO, val_to_str(pduType, pdu_types, "Unknown %d"));
					break;

				case PDUTYPE_DATA_PDU:
					dissect_ts_share_data_header(tvb, pinfo, tree);
					break;
			}
		}
	}
}

#define MCS_GLOBAL_CHANNEL 1003

#define AFTER_FRAME(pinfo, n) ((n) != 0 && (pinfo)->fd->num > (n))

// return value 1 complete, 0 go, -1 error
gint32
dissect_ts_security_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint16 flags;
	guint16 flagsHi;
    guint32 length;

    rdp_conv_info_t *rdp_info;
    proto_item *ti;
    proto_item *ti_client_info;
    proto_tree *subtree;

    rdp_info = conversation_data(pinfo);

    if(rdp_info->rdp_security == ENCRYPTION_LEVEL_NONE && AFTER_FRAME(pinfo, rdp_info->have_server_license_error_pdu))
        return 0;

	if (tree)
	{
		bytes = tvb_length_remaining(tvb, offset);

		if (bytes >= 4)
		{
			ts_security_header_offset = offset;
			flags = tvb_get_letohs(tvb, offset);
			flagsHi = tvb_get_letohs(tvb, offset + 2);
			offset += 4;

			ti = proto_tree_add_item(tree, hf_ts_security_header, tvb, ts_security_header_offset, offset - ts_security_header_offset, FALSE);
			proto_item_set_text(ti, "TS_SECURITY_HEADER, Flags = 0x%04X", flags);

            if (flags & SEC_ENCRYPT)
            {
                // TODO: decrypt
            }

            if (flags & SEC_EXCHANGE_PKT)
            {
				col_clear(pinfo->cinfo, COL_INFO);
				col_add_str(pinfo->cinfo, COL_INFO, "Client Security Exchange PDU");

                // TODO: get encrypted client random
                length = tvb_get_letohl(tvb, offset);

                return 1; 
            }
            else if (flags & SEC_INFO_PKT)
			{
				col_clear(pinfo->cinfo, COL_INFO);
				col_add_str(pinfo->cinfo, COL_INFO, "Client Info PDU");

                ti_client_info = proto_tree_add_item(tree, hf_ts_client_info_pdu, tvb, offset, -1, FALSE);

                if (!(flags & SEC_ENCRYPT))
                {
                    subtree = proto_item_add_subtree(ti_client_info, ett_ts_client_info_pdu);
                    dissect_ts_client_info_packet(tvb, pinfo, subtree);
                    return 1; 
                }
			}
            else if (flags & SEC_LICENSE_PKT)
            {
				col_clear(pinfo->cinfo, COL_INFO);
				col_add_str(pinfo->cinfo, COL_INFO, "Server License Error PDU - Valid Client");

                rdp_info->have_server_license_error_pdu = pinfo->fd->num;

                return 1;
            } 

            if (flags & SEC_ENCRYPT) // we can not decrypt this, so stop
            {
                return -1;
            }
		}
	}
}

guint32 parse_per_length(tvbuff_t *tvb)
{
    guint32 len;
    guint8 i;
    guint8 l = tvb_get_guint8(tvb, offset++);

    if (l & 0x80)
    {
        len = l & ~0x80;

        i = tvb_get_guint8(tvb, offset++);
        len = (len << 8) | i;
    }
    else
    {
        len = l;
    }
    return len;
}

guint32 parse_ber_length(tvbuff_t *tvb)
{
    guint32 len;
    guint8 i;
    guint8 l = tvb_get_guint8(tvb, offset++);

    if (l & 0x80)
    {
        l = l & ~0x80;
        len = 0;

        while (l > 0)
        {
            i = tvb_get_guint8(tvb, offset++);
            len = (len << 8) | i;
            l--;
        }
    }
    else
    {
        len = l;
    }
    return len;
}

guint32 parse_ber_header(tvbuff_t *tvb, int tag)
{
    guint32 v;

    if(tag > 0xff)
    {
        v = tvb_get_ntohs(tvb, offset);
        offset += 2;
    }
    else
    {
        v = tvb_get_guint8(tvb, offset);
        offset += 1;
    }

    if(tag != v)
        return -1;// error
        
    return parse_ber_length(tvb);
}


static void dissect_mcs_server_security_data(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_item *tree)
{
    guint32 encryption_method;
    guint32 encryption_level;
    guint32 cert_chain_version;

    guint32 server_random_len;
    guint32 server_cert_len;
    guint32 server_cert_offset;
    guint32 public_key_blob_offset;
    guint32 signature_blob_offset;
    guint16 public_key_blob_len;
    guint32 public_key_len;
    guint32 public_key_exponent;

    guint16 signature_len;

    rdp_conv_info_t *rdp_info = conversation_data(pinfo);
    rdp_info->server_port = pinfo->srcport; // sever -> client
    //rdp_info->have_server_license_error_pdu = 0; // must reset, because wireshark don't know when to close session

    encryption_method = tvb_get_letohl(tvb, offset + 4);
    encryption_level = tvb_get_letohl(tvb, offset + 8);

    proto_tree_add_item(tree, hf_ts_server_security_encryption_method, tvb, offset + 4, 4, TRUE);
    proto_tree_add_item(tree, hf_ts_server_security_encryption_level, tvb, offset + 8, 4, TRUE);

    if(encryption_level == ENCRYPTION_LEVEL_NONE)
    {
        return; // not encrypt
    }

    rdp_info->rdp_security = encryption_level; // 0 None; 1-3 CR4; 4 FIPS

    server_random_len = tvb_get_letohl(tvb, offset + 12);
    server_cert_len = tvb_get_letohl(tvb, offset + 16);

    server_cert_offset = offset + 20 + server_random_len;

    cert_chain_version = tvb_get_letohl(tvb, server_cert_offset) & 0x7fffffff;
    if(cert_chain_version == CERT_CHAIN_VERSION_1)
    {
        // dwSigAlgId, dwKeyAlgId
        assert(SIGNATURE_ALG_RSA == tvb_get_letohl(tvb, server_cert_offset + 4));
        assert(KEY_EXCHANGE_ALG_RSA == tvb_get_letohl(tvb, server_cert_offset + 8));
        
        // PublicKeyBlob
        public_key_blob_offset = server_cert_offset + 12;

        assert(BB_RSA_KEY_BLOB == tvb_get_letohs(tvb, public_key_blob_offset));
        public_key_blob_len = tvb_get_letohs(tvb, public_key_blob_offset + 2);

        public_key_len = tvb_get_letohl(tvb, public_key_blob_offset + 8); // keylen

        public_key_exponent = tvb_get_letohl(tvb, public_key_blob_offset + 20);
        proto_tree_add_item(tree, hf_ts_server_public_key_exponent, tvb, public_key_blob_offset + 20, 4, TRUE);
        proto_tree_add_item(tree, hf_ts_server_public_key_modulus, tvb, public_key_blob_offset + 24, public_key_len, TRUE);

        // SignatureBlob
        signature_blob_offset = public_key_blob_offset + 4 + public_key_blob_len;

        assert(BB_RSA_SIGNATURE_BLOB == tvb_get_letohs(tvb, signature_blob_offset));
        signature_len = tvb_get_letohs(tvb, signature_blob_offset + 2);

        proto_tree_add_item(tree, hf_ts_server_proprietary_certificate_signature, tvb, signature_blob_offset + 4, signature_len, TRUE);
        
    }
    else
    {
        // 
    }
}

#define SC_CORE 0x0c01
#define SC_SECURITY 0x0c02
#define SC_NET 0x0c03
#define SC_MCS_MSGCHANNEL 0x0C04 
#define SC_MULTITRANSPORT 0x0C08 


static void dissect_mcs_connect_response(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    guint16 type;
    guint32 len;
    proto_item *ti;
    proto_tree *mcs_connect_response_pdu_tree;
    proto_tree *server_security_data_tree;
    
    gint mcs_connect_response_pdu_offset = offset - 2;

    len = parse_ber_length(tvb);

    ti = proto_tree_add_item(tree, hf_mcs_connect_response_pdu, tvb, mcs_connect_response_pdu_offset, len + offset - mcs_connect_response_pdu_offset, TRUE);

    len = parse_ber_header(tvb, BER_TAG_RESULT);
    offset += len; // Connect-Response::result

    len = parse_ber_header(tvb, BER_TAG_INTEGER);
    offset += len; // Connect-Response::calledConnectId

    len = parse_ber_header(tvb, MCS_TAG_DOMAIN_PARAMS);
    offset += len; // Connect-Response::domainParameters

    // Connect-Response::userData
    len = parse_ber_header(tvb, BER_TAG_OCTET_STRING);
    offset += 21; // skip GCC Connection Data 

    len = parse_per_length(tvb);

    if(tvb_length_remaining(tvb, offset) >= len)
    {
		mcs_connect_response_pdu_tree = proto_item_add_subtree(ti, ett_mcs_connect_response_pdu);

        while(tvb_length_remaining(tvb, offset) > 0)
        {
            type = tvb_get_letohs(tvb, offset);
            len = tvb_get_letohs(tvb, offset + 2);

            switch(type)
            {
                case SC_CORE:
                    proto_tree_add_item(mcs_connect_response_pdu_tree, hf_mcs_connect_response_pdu_server_core_data, tvb, offset, len, TRUE);
                    break;
                case SC_NET:
                    proto_tree_add_item(mcs_connect_response_pdu_tree, hf_mcs_connect_response_pdu_server_network_data, tvb, offset, len, TRUE);
                    break;
                case SC_SECURITY:
                    ti = proto_tree_add_item(mcs_connect_response_pdu_tree, hf_mcs_connect_response_pdu_server_security_data, tvb, offset, len, TRUE);
                    server_security_data_tree = proto_item_add_subtree(ti, ett_ts_server_secutiry_data);

                    dissect_mcs_server_security_data(tvb, pinfo, server_security_data_tree); // dissect
                    break;
                case SC_MCS_MSGCHANNEL:
                    proto_tree_add_item(mcs_connect_response_pdu_tree, hf_mcs_connect_response_pdu_server_message_channel_data, tvb, offset, len, TRUE);
                case SC_MULTITRANSPORT:
                    proto_tree_add_item(mcs_connect_response_pdu_tree, hf_mcs_connect_response_pdu_server_multitransport_channel_data, tvb, offset, len, TRUE);
                default:
                    break;
            }

            offset += len;
        }

    }

}

#define CHANNEL_FLAG_FIRST 0x00000001 
#define CHANNEL_FLAG_LAST 0x00000002 
#define CHANNEL_FLAG_SHOW_PROTOCOL 0x00000010 
#define CHANNEL_FLAG_SUSPEND 0x00000020 
#define CHANNEL_FLAG_RESUME 0x00000040 
#define CHANNEL_PACKET_COMPRESSED 0x00200000 
#define CHANNEL_PACKET_AT_FRONT 0x00400000 
#define CHANNEL_PACKET_FLUSHED 0x00800000 
#define ChannelFlgasCompressionTypeMask 0x000F0000 

static void
dissect_channel_pdu_header(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    guint32 length;
    guint32 flags;

    proto_item *ti;
    guint32 flags_compression_type;
    guint8 detail_compression[128] = {'\0'};

    length = tvb_get_letohl(tvb, offset);
    flags = tvb_get_letohl(tvb, offset + 4);

    if(flags & CHANNEL_PACKET_COMPRESSED)
    {
        flags_compression_type = (flags & ChannelFlgasCompressionTypeMask) >> 16;
        g_snprintf(detail_compression, sizeof(detail_compression), ", %s", 
                val_to_str(flags_compression_type, rdp_compress_types, "Unknown %d"));
    }
    // TODO: other channel flags 

    ti = proto_tree_add_item(tree, hf_rdp_channel, tvb, offset, 8, FALSE);
    proto_item_set_text(ti, "Channel PDU Header, Length = %d %s", length,
            detail_compression);

}

static void
dissect_mcs(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint8 type;
	guint8 byte;
	guint8 flags;
	guint16 initiator;
	guint16 channelId;
	guint16 length;
	guint16 real_length;

	if (tree)
	{
		bytes = tvb_length_remaining(tvb, offset);

		if (bytes > 0)
		{
			proto_item *ti;
			type = tvb_get_bits8(tvb, offset * 8, 6);
			mcs_offset = offset++;

			/* Connect Initial and Connect Response */
			if (type == 31)
				type = tvb_get_guint8(tvb, offset++);

			col_clear(pinfo->cinfo, COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "MCS %s PDU", val_to_str(type, t125_mcs_tpdu_types, "Unknown %d"));

			switch (type)
			{
                case MCS_CONNECT_RESPONSE:
                    // get server random
                    dissect_mcs_connect_response(tvb, pinfo, tree);
                    break;

				case MCS_SEND_DATA_INDICATION:
				case MCS_SEND_DATA_REQUEST:
					initiator = tvb_get_ntohs(tvb, offset + 0); // need +1001
					channelId = tvb_get_ntohs(tvb, offset + 2); // 
					offset += 4;
					flags = tvb_get_guint8(tvb, offset++);

					byte = tvb_get_guint8(tvb, offset++);
					length = (guint16) byte;

					if (byte & 0x80)
					{
						length &= ~0x80;
						length <<= 8;
						byte = tvb_get_guint8(tvb, offset++);
						length += (guint16) byte;
					}


                    if (channelId != MCS_GLOBAL_CHANNEL)
                    {
                        col_append_fstr(pinfo->cinfo, COL_INFO, " %d", channelId);
                    }

					ti = proto_tree_add_item(tree, hf_rdp_mcs, tvb, mcs_offset, offset - mcs_offset, FALSE);
					proto_item_set_text(ti, "T.125 MCS %s PDU, Length = %d, Channel = %d", val_to_str(type, t125_mcs_tpdu_types, "Unknown %d"), length, channelId);

					real_length = tvb_length(tvb) - rdp_offset;
					if ((offset - rdp_offset) + length != real_length)
						proto_item_append_text(ti, " [Length Mismatch: %d]", real_length);

                    // 需处理 TS_SECURITY_HEADER，如果  Client MCS Connect Initial PDU with GCC Conference Create Request 定义了Client Security Data (TS_UD_CS_SEC) 
                    if(dissect_ts_security_header(tvb, pinfo, tree) == 0)
                    {
                        if (channelId == MCS_GLOBAL_CHANNEL)
                        {
                            dissect_ts_share_control_header(tvb, pinfo, tree);
                        }
                        else
                        {
                            dissect_channel_pdu_header(tvb, pinfo, tree);
                        }
                    }
					break;

				default:
					ti = proto_tree_add_item(tree, hf_rdp_mcs, tvb, mcs_offset, -1, FALSE);
					proto_item_set_text(ti, "T.125 MCS %s PDU", val_to_str(type, t125_mcs_tpdu_types, "Unknown %d"));
					break;
			}
		}
	}
}

static void
dissect_x224(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint8 type;
	guint8 length;
    gchar  msg[250] = {'\0'};

	if (tree)
	{
		bytes = tvb_length_remaining(tvb, offset);

		if (bytes > 0)
		{
			proto_item *ti;
			x224_offset = offset;
			length = tvb_get_guint8(tvb, offset);
			type = tvb_get_bits8(tvb, (offset + 1) * 8, 4);

			if (length > 1)
			{

                switch (type)
                {
                    case X224_CONNECTION_REQUEST:
                    case X224_CONNECTION_CONFIRM:
                        col_clear(pinfo->cinfo, COL_INFO);
                        col_add_fstr(pinfo->cinfo, COL_INFO, "X.224 %s PDU", val_to_str(type, x224_tpdu_types, "Unknown %d"));
                }

                if(type == X224_CONNECTION_CONFIRM && length > 7)
                {
                    guint8 nego_type = tvb_get_guint8(tvb, offset + 7);
                    guint32 nego_detail = tvb_get_letohl(tvb, offset + 11);

                    g_snprintf(msg, sizeof(msg), ": %s-", val_to_str(nego_type, nego_types, "Unknown %d"));

                    if(nego_type == TYPE_RDP_NEG_RSP)
                    {
                        strcat(msg, val_to_str(nego_detail, protocol_types, "Unknown %d"));
                        conversation_data(pinfo)->rdp_security = RDP_SECURITY_ENHANCED | nego_detail; 
                    }
                    else if(nego_type == TYPE_RDP_NEG_FAILURE)
                        strcat(msg, val_to_str(nego_detail, nego_failure_types, "Unknown %d"));
                }

				ti = proto_tree_add_item(tree, hf_rdp_x224, tvb, offset, length + 1, FALSE);
				proto_item_set_text(ti, "X.224 %s TPDU %s", val_to_str(type, x224_tpdu_types, "Unknown %d"), msg);
				offset += (length + 1);
				dissect_mcs(tvb, pinfo, tree);
			}
		}
	}
}

// event code of eventHeader
#define FASTPATH_INPUT_EVENT_SCANCODE 0x0 
#define FASTPATH_INPUT_EVENT_MOUSE 0x1 
#define FASTPATH_INPUT_EVENT_MOUSEX 0x2 
#define FASTPATH_INPUT_EVENT_SYNC 0x3 
#define FASTPATH_INPUT_EVENT_UNICODE 0x4 

// event flags of eventHeader
#define FASTPATH_INPUT_KBDFLAGS_RELEASE 0x01 
#define FASTPATH_INPUT_KBDFLAGS_EXTENDED 0x02 

#define FASTPATH_INPUT_SYNC_SCROLL_LOCK 0x01 
#define FASTPATH_INPUT_SYNC_NUM_LOCK 0x02 
#define FASTPATH_INPUT_SYNC_CAPS_LOCK 0x04 
#define FASTPATH_INPUT_SYNC_KANA_LOCK 0x08 

// mouse event pointerFlags
#define PTRFLAGS_WHEEL 0x0200 
#define PTRFLAGS_WHEEL_NEGATIVE 0x0100 
#define WheelRotationMask 0x01FF 
#define PTRFLAGS_MOVE 0x0800 
#define PTRFLAGS_DOWN 0x8000 
#define PTRFLAGS_BUTTON1 0x1000 
#define PTRFLAGS_BUTTON2 0x2000 
#define PTRFLAGS_BUTTON3 0x4000 

// extended mouse event pointerFlgas
#define PTRXFLAGS_DOWN 0x8000 
#define PTRXFLAGS_BUTTON1 0x0001 
#define PTRXFLAGS_BUTTON2 0x0002 

static const value_string fast_path_input_event_types [] = {
    { FASTPATH_INPUT_EVENT_SCANCODE, "Keyboard Event" },
    { FASTPATH_INPUT_EVENT_MOUSE, "Mouse Event" },
    { FASTPATH_INPUT_EVENT_MOUSEX, "Extended Mouse Event" },
    { FASTPATH_INPUT_EVENT_SYNC, "Synchronize Event" },
    { FASTPATH_INPUT_EVENT_UNICODE, "Unicode Keyboard Event" },
    { 0x0,	NULL }
};

static const value_string fast_path_input_keyboard_event [] = {
	{ FASTPATH_INPUT_KBDFLAGS_RELEASE, "Release" },
	{ 0x0,	NULL }
};

static const value_string input_mouse_event_buttons [] = {
    { PTRFLAGS_BUTTON1, "Button1" },
    { PTRFLAGS_BUTTON2, "Button2" },
    { PTRFLAGS_BUTTON3, "Button3 " },
    { PTRXFLAGS_BUTTON1, "Extended Mouse Button1" },
    { PTRXFLAGS_BUTTON2, "Extended Mouse Button2" },
    { 0x0,	NULL }
};


static gint32
dissect_fp_input_events(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    guint8 event_header;
    guint8 event_code;
    guint8 event_flags;

    proto_item *ti;

    guint16 key_code;
    guint16 x_pos;
    guint16 y_pos;
    guint16 pointer_flags;
    guint16 wheel_rotation;

    guint8 event_size;
    guint8 event_detail[128] = {'\0'};
    guint32 bytes_remaining;

#define GET_MOUSE_POS_FLAGS \
    pointer_flags = tvb_get_letohs(tvb, offset + 1);\
    x_pos = tvb_get_letohs(tvb, offset + 3);\
    y_pos = tvb_get_letohs(tvb, offset + 5);

    bytes_remaining = tvb_length_remaining(tvb, offset);

    while (bytes_remaining > 0)
    {
        event_header = tvb_get_guint8(tvb, offset);
        event_flags = event_header & 0x1F;
        event_code = event_header >> 5;

        // reset
        event_size = 0;
        memset(event_detail, 0, sizeof(event_detail));

        switch (event_code)
        {
            case FASTPATH_INPUT_EVENT_SCANCODE:
                key_code = tvb_get_guint8(tvb, offset + 1); 
                g_snprintf(event_detail, sizeof(event_detail), "Key %s, %sCode: %X", 
                        val_to_str(event_flags & FASTPATH_INPUT_KBDFLAGS_RELEASE, fast_path_input_keyboard_event, "Down"),
                        event_flags & FASTPATH_INPUT_KBDFLAGS_EXTENDED ? "Extended " : "",
                        key_code);
                event_size = 2;
                break;

            case FASTPATH_INPUT_EVENT_MOUSE:
                GET_MOUSE_POS_FLAGS;

                if (pointer_flags & PTRFLAGS_WHEEL)
                {
                    wheel_rotation = pointer_flags & (WheelRotationMask & ~PTRFLAGS_WHEEL_NEGATIVE);
                    wheel_rotation *= pointer_flags & PTRFLAGS_WHEEL_NEGATIVE ? -1 : 1;
                    
                    g_snprintf(event_detail, sizeof(event_detail), "Wheel Rotation %d", wheel_rotation);
                }
                else if (pointer_flags & PTRFLAGS_MOVE)
                {
                    g_snprintf(event_detail, sizeof(event_detail), "Move (%d, %d)", x_pos, y_pos);
                }
                else
                {
                    g_snprintf(event_detail, sizeof(event_detail), "%s %s (%d, %d)", 
                            val_to_str(pointer_flags & 0x7000, input_mouse_event_buttons, "Ukown Button %d"),
                            pointer_flags & PTRFLAGS_DOWN ? "Down" : "Up",
                            x_pos, y_pos);
                }

                event_size = 7;
                break;

            case FASTPATH_INPUT_EVENT_MOUSEX:
                GET_MOUSE_POS_FLAGS;

                g_snprintf(event_detail, sizeof(event_detail), "%s %s (%d, %d)", 
                        val_to_str(pointer_flags & 0x0003, input_mouse_event_buttons, "Ukown Button %d"),
                        pointer_flags & PTRXFLAGS_DOWN ? "Down" : "Up",
                        x_pos, y_pos);

                event_size = 7;
                break;

            case FASTPATH_INPUT_EVENT_SYNC:
                event_size = 1;
                break;

            case FASTPATH_INPUT_EVENT_UNICODE:
                key_code = tvb_get_letohs(tvb, offset + 1); 
                g_snprintf(event_detail, sizeof(event_detail), "Key %s, Code: %X", 
                        val_to_str(event_flags & FASTPATH_INPUT_KBDFLAGS_RELEASE, fast_path_input_keyboard_event, "Down"),
                        key_code);
                event_size = 3;
                break;

            default:
                // never reach here
                event_size = bytes_remaining;
                g_snprintf(event_detail, sizeof(event_detail), "Error!");
        }

        ti = proto_tree_add_item(tree, hf_ts_input_event, tvb, offset, event_size, TRUE);
        proto_item_set_text(ti, "%s, %s", val_to_str(event_code, fast_path_input_event_types, "Unknown %d"), event_detail);

        offset += event_size;
        bytes_remaining = tvb_length_remaining(tvb, offset);
    }

    return 0;
}

#define TS_STANDARD  0x01 
#define TS_SECONDARY  0x02 


static void
dissect_order_data(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
// primary drawing order, alternate secondary drawing order hard to extract length

}



static gint32
dissect_fp_updates(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
    guint8 update_header;
    guint8 compression_flgas;
    guint16 size;

    guint8 update_code;
    guint8 fragmentation;
    guint8 compression;

    proto_item *ti;
    guint8 update_detail[256] = {'\0'};
    gint32 update_detail_offset = 0;
    guint32 bytes_remaining;
    guint32 update_header_offset;

    bytes_remaining = tvb_length_remaining(tvb, offset);

    while(bytes_remaining > 0)
    {
        // reset
        memset(update_detail, 0, sizeof(update_detail));
        update_detail_offset = 0;
        update_header_offset = offset;

        update_header = tvb_get_guint8(tvb, offset++);
        update_code = update_header & 0x0F;
        fragmentation = (update_header >> 4) & 0x3;
        compression = (update_header >> 6) & 0x3;

        if (compression == FASTPATH_OUTPUT_COMPRESSION_USED)
        {
            compression_flgas = tvb_get_guint8(tvb, offset++);

            update_detail_offset += g_snprintf(update_detail, sizeof(update_detail), ", %s",
                    val_to_str(compression_flgas & CompressionTypeMask, rdp_compress_types, "Unknown %d"));
            // TODO: decompress
        }

        size = tvb_get_letohs(tvb, offset);
        offset += 2;

        // if not compression, then dissect ORDER
        if (compression != FASTPATH_OUTPUT_COMPRESSION_USED && update_code == FASTPATH_UPDATETYPE_ORDERS)
        {
            guint16 idx;
            guint16 number_orders = tvb_get_letohs(tvb, offset);
            g_snprintf(update_detail + update_detail_offset, array_length(update_detail) - update_detail_offset, ", Order number %d", number_orders);

            for (idx = 0; idx < number_orders; ++idx)
            {
                dissect_order_data(tvb_new_subset_remaining(tvb, offset + 2), pinfo, tree);
            }
        }


        ti = proto_tree_add_item(tree, hf_ts_output_update, tvb, update_header_offset, offset - update_header_offset + size, TRUE);
        proto_item_set_text(ti, "%s, Fragment %s %s", 
                val_to_str(update_code, fast_path_output_update_types, "Unknown %d"), 
                val_to_str(fragmentation, fast_path_fragment_types, "Unknown %d"),
                update_detail);

        offset += size;
        bytes_remaining = tvb_length_remaining(tvb, offset);
    }

    return 0;
}


static void
dissect_tpkt(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	guint8 version;
	guint16 length;
    guint8 num_events;
    guint8 sec_flags;

    gboolean is_input;

    proto_tree *ts_input_events_tree;
    proto_tree *ts_output_updates_tree;

	if (tree)
	{
		bytes = tvb_length_remaining(tvb, offset);

		if (bytes >= 4)
		{
			proto_item *ti;
			version = tvb_get_guint8(tvb, offset);
			length = tvb_get_ntohs(tvb, offset + 2);

			if (version == 3)
			{
				tpkt_offset = offset;
				ti = proto_tree_add_item(tree, hf_rdp_tpkt, tvb, 0, 4, FALSE);
				proto_item_set_text(ti, "TPKT Header, Length = %d", length);
				offset += 4;
				dissect_x224(tvb, pinfo, tree);
			}
            else if ((version & 0x03) == FASTPATH_INPUT_ACTION_FASTPATH )
            {
                is_input = conversation_data(pinfo)->server_port == pinfo->destport; 
                num_events = (version >> 2) & 0x0F;
                sec_flags = version >> 6;

                ++offset;
                length = parse_per_length(tvb);

                if(length != bytes) 
                    return;


                if (sec_flags & FASTPATH_INPUT_ENCRYPTED) // why not encrypted, but set FASTPATH_INPUT_SECURE_CHECKSUM
                {
                    offset += 4;
                    if (sec_flags & FASTPATH_INPUT_SECURE_CHECKSUM)
                        offset += 8;
                    // TODO: FIPS decrypt
                }
                else
                {
                    if (is_input)// packet only client -> server
                    {
                        if (num_events == 0)// if numEvents == 0, then after fips dataSignature
                        {
                            num_events = tvb_get_guint8(tvb, offset++);
                        }

                        ti = proto_tree_add_item(tree, hf_client_fastinput_event_pdu, tvb, 0, offset, FALSE);
                        proto_item_set_text(ti, "Client Fast-Path Input Event PDU, Length = %d, Events = %d, %s", (int)length, (int)num_events, val_to_str(sec_flags, fast_path_input_event_security, ""));

                        ti = proto_tree_add_item(tree, hf_client_fastpath_input_events, tvb, offset, -1, FALSE);
                        ts_input_events_tree = proto_item_add_subtree(ti, ett_ts_input_events);

                        dissect_fp_input_events(tvb, pinfo, ts_input_events_tree);

                        col_clear(pinfo->cinfo, COL_INFO);
                        col_add_str(pinfo->cinfo, COL_INFO, "Client Fast-Path Input Event PDU");
                    }
                    else
                    {
                        ti = proto_tree_add_item(tree, hf_server_fastpath_output_pdu, tvb, 0, offset, FALSE);
                        proto_item_set_text(ti, "Server Fast-Path Output Update PDU, Length = %d, %s", (int)length, val_to_str(sec_flags, fast_path_input_event_security, ""));

                        ti = proto_tree_add_item(tree, hf_server_fastpath_outputs, tvb, offset, -1, FALSE);
                        ts_output_updates_tree = proto_item_add_subtree(ti, ett_ts_output_updates);

                        dissect_fp_updates(tvb, pinfo, ts_output_updates_tree);

                        col_clear(pinfo->cinfo, COL_INFO);
                        col_add_str(pinfo->cinfo, COL_INFO, "Server Fast-Path Update PDU");
                    }
                }

            }
		}
	}
}

static void
dissect_rdp(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree)
{
	if (tree)
	{
		offset = 0;
		bytes = tvb_length_remaining(tvb, 0);

		if (bytes > 0)
		{
			proto_item *ti;
			proto_tree *rdp_tree;

			rdp_offset = offset;
			ti = proto_tree_add_item(tree, proto_rdp, tvb, 0, -1, FALSE);
			rdp_tree = proto_item_add_subtree(ti, ett_rdp);

			col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDP");

			dissect_tpkt(tvb, pinfo, rdp_tree);
		}
	}
}

void
proto_register_ts_caps_set(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_ts_caps_set_capability_set_type,
		  { "capabilitySetType", "rdp.capset_type", FT_UINT16, BASE_DEC, VALS(capability_set_types), 0x0, NULL, HFILL } },
		{ &hf_ts_caps_set_length_capability,
		  { "lengthCapability", "rdp.capset_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_caps_set_capability_data,
		  { "capabilityData", "rdp.capset_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } }
	};

	static gint *ett[] = {
		&ett_ts_caps_set
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_ts_capability_sets(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_ts_caps_set,
		  { "capabilitySet", "rdp.capset", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } }
	};

	static gint *ett[] = {
		&ett_ts_capability_sets
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_ts_input_events(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_ts_input_event,
		  { "inputEvent", "rdp.input_event", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } }
	};

	static gint *ett[] = {
		&ett_ts_input_events
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_ts_output_updates(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_ts_output_update,
		  { "outputUpdate", "rdp.input_event", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } }
	};

	static gint *ett[] = {
		&ett_ts_output_updates
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_register_ts_server_security_data(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_ts_server_security_encryption_method,
		  { "serverSecurityEncryptionMethod", "rdp.server_enc_method", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_server_security_encryption_level,
		  { "serverSecurityEncryptionLevel", "rdp.server_enc_level", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_server_public_key_modulus,
		  { "serverPublicKeyModulus", "rdp.server_modulus", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_server_public_key_exponent,
		  { "serverPublicKeyExponent", "rdp.server_exponent", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_server_proprietary_certificate_signature,
		  { "serverProprietaryCertificateSignature", "rdp.server_signature", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_ts_server_secutiry_data
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_register_mcs_connect_response_pdu(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_mcs_connect_response_pdu_server_core_data,
		  { "serverCoreData", "rdp.server_core", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_mcs_connect_response_pdu_server_network_data,
		  { "serverNetworkData", "rdp.server_network", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_mcs_connect_response_pdu_server_security_data,
		  { "serverSecurityData", "rdp.server_security", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_mcs_connect_response_pdu_server_message_channel_data,
		  { "serverMessageChannelData", "rdp.server_message_channel", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_mcs_connect_response_pdu_server_multitransport_channel_data,
		  { "serverMultitransportChannelData", "rdp.server_multi_channel", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_mcs_connect_response_pdu
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_register_ts_confirm_active_pdu(void)
{
	static hf_register_info hf[] =
	{
		{ &hf_ts_confirm_active_pdu_shareid,
		  { "shareId", "rdp.shareid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu_originatorid,
		  { "originatorId", "rdp.originatorid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu_length_source_descriptor,
		  { "lengthSourceDescriptor", "rdp.len_src_desc", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu_length_combined_capabilities,
		  { "lengthCombinedCapabilities", "rdp.caplen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu_source_descriptor,
		  { "sourceDescriptor", "rdp.src_desc", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu_number_capabilities,
		  { "numberCapabilities", "rdp.capnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu_pad2octets,
		  { "pad2Octets", "rdp.pad2octets", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_capability_sets,
		  { "capabilitySets", "rdp.capsets", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_demand_active_pdu_sessionid,
		  { "sessionId", "rdp.demand_active_pdu_sessionid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } }
	};

	static gint *ett[] = {
		&ett_ts_confirm_active_pdu
	};

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett)); // tree id is used to expanded/collapsed state of the subtree
}

void
proto_register_rdp(void)
{
	module_t *module_rdp;

	static hf_register_info hf[] =
	{
		{ &hf_rdp_rdp,
		  { "rdp", "rdp", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_rdp_tpkt,
		  { "TPKT Header", "rdp.tpkt", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_rdp_x224,
		  { "X.224 Header", "rdp.x224", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_rdp_mcs,
		  { "MCS Header", "rdp.mcs", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_rdp_channel,
		  { "Channel PDU Header", "rdp.channel", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_security_header,
		  { "TS_SECURITY_HEADER", "rdp.sec", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_client_info_pdu,
		  { "Client Info PDU", "rdp.client_info", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_share_control_header,
		  { "TS_SHARE_CONTROL_HEADER", "rdp.share_ctrl", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_share_data_header,
		  { "TS_SHARE_DATA_HEADER", "rdp.share_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_confirm_active_pdu,
		  { "Confirm Active PDU", "rdp.confirm_active", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_ts_demand_active_pdu,
		  { "Demand Active PDU", "rdp.demand_active", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_mcs_connect_response_pdu,
		  { "MCS Connect Response PDU", "rdp.connect_response", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_client_fastinput_event_pdu,
		  { "Client Fast-Path Input Event PDU", "rdp.fp_input", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_client_fastpath_input_events,
		  { "fpInputEvents", "rdp.fp_input_events", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_server_fastpath_output_pdu,
		  { "Server Fast-Path Update PDU", "rdp.fp_update", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_server_fastpath_outputs,
		  { "fpOutputUpdates", "rdp.fp_output_updates", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_server_slowpath_graphics_update,
		  { "Server Graphics Update PDU", "rdp.sp_graphics_update", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_server_slowpath_pointer_update,
		  { "Server Pointer Update PDU", "rdp.sp_pointer_update", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        // Client Info PDU
        { &hf_ts_client_info_pdu_codepage,
            { "codepage", "rdp.client_info_pdu_codepage", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_flags,
            { "flags", "rdp.client_info_pdu_flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_domain_len,
            { "domain_len", "rdp.client_info_pdu_domain_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_user_name_len,
            { "user_name_len", "rdp.client_info_pdu_user_name_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_password_len,
            { "password_len", "rdp.client_info_pdu_password_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_alternate_shell_len,
            { "alternate_shell_len", "rdp.client_info_pdu_alternate_shell_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_working_dir_len,
            { "working_dir_len", "rdp.client_info_pdu_working_dir_len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_ts_client_info_pdu_domain,
            { "domain", "rdp.client_info_pdu_domain", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_user_name,
            { "user_name", "rdp.client_info_pdu_user_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_password,
            { "password", "rdp.client_info_pdu_password", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_alternate_shell,
            { "alternate_shell", "rdp.client_info_pdu_alternate_shell", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ts_client_info_pdu_working_dir,
            { "working_dir", "rdp.client_info_pdu_working_dir", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

	};

	static gint *ett[] = {
		&ett_rdp,
        &ett_ts_client_info_pdu,

	};

	proto_rdp = proto_register_protocol("Remote Desktop Protocol", "RDP", "rdp");
	register_dissector("rdp", dissect_rdp, proto_rdp);

	proto_register_field_array(proto_rdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
    proto_register_mcs_connect_response_pdu();
    proto_register_ts_server_security_data();
    proto_register_ts_input_events();
    proto_register_ts_output_updates();
	module_rdp = prefs_register_protocol( proto_rdp, proto_reg_handoff_rdp);
}

void
proto_reg_handoff_rdp(void)
{
	dissector_handle_t rdp_handle;

	rdp_handle = find_dissector("rdp");
	dissector_add_uint("tcp.port", TCP_PORT_RDP, rdp_handle);

}

