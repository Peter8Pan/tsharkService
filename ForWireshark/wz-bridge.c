#define USE_wzBridge2
#ifndef USE_wzBridge
#include "wz-bridge.h"

static DWORD exceptFilter(struct _EXCEPTION_POINTERS* exInf)
{
	char szBuf[300];
	sprintf(szBuf, "Operation failed with exception code = %d", exInf->ExceptionRecord->ExceptionCode);
	MessageBoxA(NULL, szBuf, "Trace", MB_APPLMODAL | MB_OK);
	return EXCEPTION_EXECUTE_HANDLER;
}

capture_file cfile;
wz_LoadFileStatus loadFileStatus;
wz_LoadParameters* pLoadParameters;
const int FrameInfoCount = 2; //index, time

typedef enum {
	OUTPUT_FRAME_SUMMARY = 0x01,
	OUTPUT_FIELD_VALUE = 0x02,
	OUTPUT_STAT = 0x04,
	OUTPUT_FRAME_DETAIL = 0x08
} wz_output_type;

#pragma region collect field value
static const guint8 * wz_get_field_data(GSList *src_list, field_info *fi)
{

	GSList   *src_le;
	tvbuff_t *src_tvb;
	gint      length, tvbuff_length;
	struct data_source *src;

	for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
		src = (struct data_source *)src_le->data;
		src_tvb = get_data_source_tvb(src);
		if (fi->ds_tvb == src_tvb) {
			/*
			* Found it.
			*
			* XXX - a field can have a length that runs past
			* the end of the tvbuff.  Ideally, that should
			* be fixed when adding an item to the protocol
			* tree, but checking the length when doing
			* that could be expensive.  Until we fix that,
			* we'll do the check here.
			*/
			tvbuff_length = tvb_captured_length_remaining(src_tvb,
				fi->start);
			if (tvbuff_length < 0) {
				return NULL;
			}
			length = fi->length;
			if (length > tvbuff_length)
				length = tvbuff_length;
			return tvb_get_ptr(src_tvb, fi->start, length);
		}
	}
	g_assert_not_reached();
	return NULL;  /* not found */
}
static guint8* wz_get_field_bytes_value(GSList *src_list, field_info *fi)
{
	guint8* pOrigValue;
	guint8* pValue;
	if (!fi->ds_tvb)
		return NULL;

	if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start))
		return NULL;

	/* Find the data for this field. */
	pOrigValue = wz_get_field_data(src_list, fi);
	if (pOrigValue == NULL)
		return NULL;

	pValue = malloc(fi->length);
	memcpy(pValue, pOrigValue, fi->length);
	return pValue;
}
static void wz_output_fields_new(wz_output_fields* fields)
{
	fields->print_bom = FALSE;
	fields->print_header = FALSE;
	fields->separator = '\t';
	fields->occurrence = 'a';
	fields->aggregator = ',';
	fields->fields = NULL; /*Do lazy initialisation */
	fields->field_indicies = NULL;
	fields->field_values = NULL;
	fields->quote = '\0';
	fields->includes_col_fields = FALSE;
}
static void wz_output_fields_add(wz_output_fields *fields, const gchar *field)
{
	g_assert(fields);
	g_assert(field);


	if (NULL == fields->fields) {
		fields->fields = g_ptr_array_new();
	}

	g_ptr_array_add(fields->fields, field);

	/* See if we have a column as a field entry */
	if (!strncmp(field, COLUMN_FIELD_FILTER, strlen(COLUMN_FIELD_FILTER)))
		fields->includes_col_fields = TRUE;
}
static void get_specified_fields(wz_LoadFileStatus *pLoadFileStatus, frame_data* pFrame_data)
{
	gboolean first = TRUE;
	gint      col;
	gchar    *col_name;
	gpointer  field_index;
	int indx;
	guint8 dummy1 = 1;
	guint8 dummy0 = 0;

	g_assert(pLoadFileStatus->output_fields.fields);
	g_assert(pLoadFileStatus->edt);

	wz_proto_tree_children_foreach(pLoadFileStatus, pLoadFileStatus->edt->tree);

	if (pLoadFileStatus->output_fields.includes_col_fields) {
		for (col = 0; col < pLoadFileStatus->cfile.cinfo.num_cols; col++) {
			/* Prepend COLUMN_FIELD_FILTER as the field name */
			col_name = g_strdup_printf("%s%s", COLUMN_FIELD_FILTER, pLoadFileStatus->cfile.cinfo.columns[col].col_title);
			field_index = g_hash_table_lookup(pLoadFileStatus->output_fields.field_indicies, col_name);
			g_free(col_name);

			if (NULL != field_index) {
				/* Unwrap change made to disambiguiate zero / null */
				indx = GPOINTER_TO_UINT(field_index) - 1;
				pLoadFileStatus->output_fields.field_values[indx] = pLoadFileStatus->cfile.cinfo.columns[col].col_data;
			}
		}
	}

	wz_LoadResult* pLoadResult = pLoadFileStatus->pLoadResult;
	BOOL hasValue = FALSE;
	//pre-process to see if a protocol has value
	for (int i = 0; i < pLoadFileStatus->output_fields.fields->len; ++i)
	{
		int start = i;
		hasValue = FALSE;
		for (; i < pLoadFileStatus->output_fields.fields->len; ++i)
		{
			if (pLoadFileStatus->output_fields.field_values[i] != NULL)
				hasValue = TRUE;

			if (i + 1 >= pLoadFileStatus->output_fields.fields->len)
				break;

			if (pLoadResult->FieldNeedIndexArray[i + 1] == 1)
				break;
		}
		int end = i;
		for (int m = start; m <= end; ++m)
			pLoadResult->FieldNeedSaved[m] = hasValue == TRUE ? 1 : 0;
	}

	INT64 frameIndex = 0;
	for (int fieldIndex = 0; fieldIndex < pLoadFileStatus->output_fields.fields->len; ++fieldIndex)
	{
		if (pLoadResult->FieldNeedSaved[fieldIndex] == 0)
			continue;

		//frame index of the data
		if (pLoadResult->FieldNeedIndexArray[fieldIndex] == 1)
		{
			if (pLoadResult->FieldIndexArrays[fieldIndex] == NULL)
				pLoadResult->FieldIndexArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(INT64)); //save time 

			if (pLoadResult->FrameIndexInsteadOfTime == 0)
			{
				INT64 lTime = pFrame_data->abs_ts.secs * 10000000 + pFrame_data->abs_ts.nsecs / 100; //ticks
				g_array_append_val(pLoadResult->FieldIndexArrays[fieldIndex], lTime);
			}
			else
			{
				frameIndex = (INT64)pLoadFileStatus->frameIndex;
				g_array_append_val(pLoadResult->FieldIndexArrays[fieldIndex], frameIndex);
			}
			/*if (pLoadResult->FieldIndexArrays[fieldIndex] == NULL)
				pLoadResult->FieldIndexArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(UINT32));
			g_array_append_val(pLoadResult->FieldIndexArrays[fieldIndex], pLoadFileStatus->frameIndex);*/
		}

		gpointer pValue = pLoadFileStatus->output_fields.field_values[fieldIndex];
		hasValue = true;
		switch (pLoadResult->output_field_ftype[fieldIndex])
		{
#pragma region
		case FT_NONE:	/* used for text labels with no value */
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(guint8));

			if(pValue==1234321)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], dummy1);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], dummy0);
			break;
		}
		case FT_PROTOCOL:
		case FT_STRING:
		case FT_STRINGZ:	/* for use with proto_tree_add_item() */
		case FT_UINT_STRING:	/* for use with proto_tree_add_item() */
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(char*));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
			{
				char* dummyNull = NULL;
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], dummyNull);
			}
			else
			{
				char* newStr = g_strdup(((fvalue_t*)pValue)->value.strbuf);
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], newStr);
			}
			break;
		}
		case FT_BOOLEAN:	/* TRUE and FALSE come from <glib.h> */
		case FT_UINT8:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(guint8));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], UI8_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (guint8)((fvalue_t*)pValue)->value.uinteger);
			break;
		}
		case FT_IEEE_11073_SFLOAT: //uint16
		case FT_UINT16:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(guint16));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], UI16_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (guint16)((fvalue_t*)pValue)->value.uinteger);
			break;
		}
		case FT_IEEE_11073_FLOAT: //uint32
		case FT_UINT24:	/* really a UINT32: but displayed as 6 hex-digits if FD_HEX*/
		case FT_UINT32:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(guint32));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], UI32_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], ((fvalue_t*)pValue)->value.uinteger);
			break;
		}
		case FT_UINT40:	/* really a UINT64: but displayed as 10 hex-digits if FD_HEX*/
		case FT_UINT48:	/* really a UINT64: but displayed as 12 hex-digits if FD_HEX*/
		case FT_UINT56:	/* really a UINT64: but displayed as 14 hex-digits if FD_HEX*/
		case FT_UINT64:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(guint64));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], UI64_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], ((fvalue_t*)pValue)->value.uinteger64);
			break;
		}
		case FT_INT8:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(gint8));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], I8_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (gint8)((fvalue_t*)pValue)->value.sinteger);
			break;
		}
		case FT_INT16:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(gint16));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], I16_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (gint16)((fvalue_t*)pValue)->value.sinteger);
			break;
		}
		case FT_INT24:	/* same as for UINT24 */
		case FT_INT32:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(gint32));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], I32_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (gint32)((fvalue_t*)pValue)->value.sinteger);
			break;
		}
		case FT_INT40: /* same as for UINT40 */
		case FT_INT48: /* same as for UINT48 */
		case FT_INT56: /* same as for UINT56 */
		case FT_INT64:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(gint64));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], I64_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (gint64)((fvalue_t*)pValue)->value.sinteger64);
			break;
		}
		case FT_FLOAT:
		case FT_DOUBLE:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(gdouble));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], F_MAX);
			else
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], (gdouble)((fvalue_t*)pValue)->value.floating);
			break;
		}
		case FT_ABSOLUTE_TIME:
		case FT_RELATIVE_TIME:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(INT64));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], I64_MAX);
			else
			{
				INT64 lTime = ((fvalue_t*)pValue)->value.time.secs * 10000000 + ((fvalue_t*)pValue)->value.time.nsecs / 100; //ticks
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], lTime);
			}
			break;
			break;
		}
		case FT_ETHER:
		{
			break;
		}
		case FT_BYTES:
		case FT_UINT_BYTES:
		{
			if (pLoadResult->FieldDataArrays[fieldIndex] == NULL)
				pLoadResult->FieldDataArrays[fieldIndex] = g_array_new(FALSE, FALSE, sizeof(GByteArray*));

			if (pLoadFileStatus->output_fields.field_values[fieldIndex] == NULL)
			{
				GByteArray* dummyNull = NULL;
				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], dummyNull);
			}
			else
			{
				GByteArray *array = g_byte_array_new();
				array = g_byte_array_append(array, ((fvalue_t*)pValue)->value.bytes->data, ((fvalue_t*)pValue)->value.bytes->len);

				g_array_append_val(pLoadResult->FieldDataArrays[fieldIndex], array);
			}
			break;
		}
		case FT_IPv4:
		case FT_IPv6:
		case FT_IPXNET:
		case FT_FRAMENUM:	/* a UINT32: but if selected lets you go to frame with that number */
		//case FT_PCRE:	/* a compiled Perl-Compatible Regular Expression object */
		case FT_GUID:	/* GUID: UUID */
		case FT_OID:		/* OBJECT IDENTIFIER */
		case FT_EUI64:
		case FT_AX25:
		case FT_VINES:
		case FT_REL_OID:	/* RELATIVE-OID */
		case FT_SYSTEM_ID:
		case FT_STRINGZPAD:	/* for use with proto_tree_add_item() */
		case FT_FCWWN:
		case FT_NUM_TYPES: /* last item number plus one */
			break;
#pragma endregion
		}
		pLoadFileStatus->output_fields.field_values[fieldIndex] = NULL;
	}

	////frame info: frame index, time
	//if (false && hasValue) //disable saving frame index and time in seperate array, instead, save time directly to the above "FieldIndexArrays"
	//{
	//	//get frame info
	//	g_array_append_val(pLoadResult->FrameInfo[0], pLoadFileStatus->frameIndex);
	//	double dTime = (double)pFrame_data->abs_ts.secs + (double)pFrame_data->abs_ts.nsecs / (double)1000000000;
	//	g_array_append_val(pLoadResult->FrameInfo[1], dTime);

	//	//get conversation
	//	//packet_info pi = pLoadFileStatus->edt->pi;
	//	//pi.srcport
	//}
}
static void wz_proto_tree_get_node_field_values(wz_LoadFileStatus *pLoadFileStatus, proto_node *node)
{
	gpointer pValue;
	gpointer* pFieldValues;

	field_info *fi = PNODE_FINFO(node);

	/* dissection with an invisible proto tree? */
	g_assert(fi);

	gpointer field_index = g_hash_table_lookup(pLoadFileStatus->output_fields.field_indicies, fi->hfinfo->abbrev);
	if (NULL != field_index)
	{
		pFieldValues = pLoadFileStatus->output_fields.field_values;
		wz_LoadResult* pLoadResult = pLoadFileStatus->pLoadResult;

		/* Unwrap change made to disambiguiate zero / null */
		int indx = GPOINTER_TO_UINT(field_index) - 1;
		if (pLoadFileStatus->output_fieldLoadFlags[indx] == 1 && pFieldValues[indx] != NULL)
		{
		}
		else
		{
			if (fi->hfinfo->id == hf_text_only) {
				pLoadResult->output_field_ftype[indx] = FT_STRING;
				/* Text label.
				* Get the text */
				if (fi->rep) {
					pValue = fi->rep->representation;
				}
				else {
					pValue = wz_get_field_bytes_value(pLoadFileStatus->edt->pi.data_src, fi);
				}
			}
			else if (fi->hfinfo->id == proto_data) {
				pLoadResult->output_field_ftype[indx] = FT_BYTES;
				/* Uninterpreted data, i.e., the "Data" protocol, is
				* printed as a field instead of a protocol. */
				pValue = wz_get_field_bytes_value(pLoadFileStatus->edt->pi.data_src, fi);
			}
			else {
				/* Normal protocols and fields */
				gchar      *dfilter_string;
				pLoadResult->output_field_ftype[indx] = fi->hfinfo->type;
				switch (fi->hfinfo->type)
				{
				case FT_PROTOCOL:
					/* Print out the full details for the protocol. */
					if (fi->rep) {
						pValue = fi->rep->representation;
					}
					else {
						/* Just print out the protocol abbreviation */
						pValue = fi->hfinfo->abbrev;
					}
					break;
				case FT_NONE:
					/* Return "1" so that the presence of a field of type
					* FT_NONE can be checked when using -T fields */
					pValue = 1234321;
					break;
				default:

					pValue = &fi->value;
					break;
				}
			}

			switch (pLoadFileStatus->output_fieldLoadFlags[indx])
			{
			case 1:  //first one
			case 9:
				pFieldValues[indx] = pValue;
				break;
			case 0:
				if (pFieldValues[indx] == NULL)
					pFieldValues[indx] = g_ptr_array_new();
				g_ptr_array_add(pFieldValues[indx], pValue);
				break;
			}
		}
	}

	/* Recurse here. */
	if (node->first_child != NULL) {
		wz_proto_tree_children_foreach(pLoadFileStatus, node);
	}
}
static void wz_proto_tree_children_foreach(wz_LoadFileStatus *pLoadFileStatus, proto_tree *tree)
{
	proto_node *node = tree;
	proto_node *current;

	if (!node)
		return;

	node = node->first_child;
	while (node != NULL) {
		current = node;
		node = current->next;
		wz_proto_tree_get_node_field_values(pLoadFileStatus, (proto_tree *)current);
	}
}
#pragma endregion
#pragma region frame list
typedef struct _wz_frame_info {
	guint32 frameNum;
	gint64 filePosition;
	double time;
	char* srcAddress;
	char* dstAddress;
	char* protocol;
	guint32 length;
	char* keyInfo;
} wz_frame_info;
wz_frame_info gFrameInfo;
static void wz_print_columns(capture_file *cf, wz_frame_info* pInfo, gboolean allInfo)
{
	char   *line_bufp;
	int     i;
	size_t  buf_offset;
	size_t  column_len;
	size_t  col_len;
	col_item_t* col_item;

	line_bufp = get_line_buf(256);
	buf_offset = 0;
	*line_bufp = '\0';
	for (i = 0; i < cf->cinfo.num_cols; i++) {
		col_item = &cf->cinfo.columns[i];
		/* Skip columns not marked as visible. */
		if (!get_column_visible(i))
			continue;
		switch (col_item->col_fmt) {
		case COL_NUMBER:
			continue;

		case COL_CLS_TIME:
		case COL_REL_TIME:
		case COL_ABS_TIME:
		case COL_ABS_YMD_TIME:  /* XXX - wider */
		case COL_ABS_YDOY_TIME: /* XXX - wider */
		case COL_UTC_TIME:
		case COL_UTC_YMD_TIME:  /* XXX - wider */
		case COL_UTC_YDOY_TIME: /* XXX - wider */
			continue;

		case COL_DEF_SRC:
		case COL_RES_SRC:
		case COL_UNRES_SRC:
		case COL_DEF_DL_SRC:
		case COL_RES_DL_SRC:
		case COL_UNRES_DL_SRC:
		case COL_DEF_NET_SRC:
		case COL_RES_NET_SRC:
		case COL_UNRES_NET_SRC:
			if (allInfo) pInfo->srcAddress = g_strdup(col_item->col_data);
			continue;

		case COL_DEF_DST:
		case COL_RES_DST:
		case COL_UNRES_DST:
		case COL_DEF_DL_DST:
		case COL_RES_DL_DST:
		case COL_UNRES_DL_DST:
		case COL_DEF_NET_DST:
		case COL_RES_NET_DST:
		case COL_UNRES_NET_DST:
			if (allInfo) pInfo->dstAddress = g_strdup(col_item->col_data);
			continue;
		case COL_PACKET_LENGTH:
			continue;
		case COL_PROTOCOL:
			if (allInfo) pInfo->protocol = g_strdup(col_item->col_data);
			continue;
		default:
			column_len = strlen(col_item->col_data);
			line_bufp = get_line_buf(buf_offset + column_len + 1);

			put_string(line_bufp + buf_offset, col_item->col_data, column_len);
			buf_offset += column_len;

			put_string(line_bufp + buf_offset, " ", 1);
			buf_offset += 1;
			break;
		}
	}
	pInfo->keyInfo = g_strdup(line_bufp);
}
static void get_frame_list(wz_LoadFileStatus *pLoadFileStatus, frame_data* pFrame_data)
{
	/* Just fill in the columns. */
	epan_dissect_fill_in_columns(pLoadFileStatus->edt, FALSE, TRUE);

	wz_frame_info* pInfo = NULL;
	if (pLoadParameters->outputFlag & OUTPUT_FRAME_SUMMARY)
	{
		//get frame info
		pInfo = malloc(sizeof(wz_frame_info));
		pInfo->time = (double)pFrame_data->abs_ts.secs + (double)pFrame_data->abs_ts.nsecs / (double)1000000000;
		pInfo->dstAddress = NULL;
		pInfo->srcAddress = NULL;
		pInfo->keyInfo = NULL;
		pInfo->length = pFrame_data->pkt_len;
		pInfo->protocol = NULL;
	}
	else
		pInfo = &gFrameInfo;
	pInfo->frameNum = pLoadFileStatus->frameIndex;
	pInfo->filePosition = pLoadFileStatus->data_offset;

	wz_print_columns(&pLoadFileStatus->cfile, pInfo, pLoadParameters->outputFlag & OUTPUT_FRAME_SUMMARY);

	if (pLoadParameters->outputFlag & OUTPUT_FRAME_SUMMARY)
	{
		if (pLoadFileStatus->pLoadResult->FrameSummary == NULL)
			pLoadFileStatus->pLoadResult->FrameSummary = g_ptr_array_new();
		g_ptr_array_add(pLoadFileStatus->pLoadResult->FrameSummary, pInfo);
	}
}
#pragma endregion
#pragma region frame detail

typedef struct {
	int                  level;
	print_stream_t      *stream;
	gboolean             success;
	GSList              *src_list;
	print_dissections_e  print_dissections;
	gboolean             print_hex_for_data;
	packet_char_enc      encoding;
	GHashTable          *output_only_tables; /* output only these protocols */
} wz_print_data;
static void wz_proto_tree_children_foreach_frame_detail(wz_simple_treenode *pSimple_tree_node, proto_tree *tree, gpointer data);
static void wz_proto_tree_print_node_detail(wz_simple_treenode *pSimple_tree_node, proto_node *node, gpointer data)
{
	field_info   *fi = PNODE_FINFO(node);
	wz_print_data   *pdata = (wz_print_data*)data;
	const guint8 *pd;
	gchar         label_str[ITEM_LABEL_LENGTH];
	gchar        *label_ptr;

	/* dissection with an invisible proto tree? */
	g_assert(fi);

	/* Don't print invisible entries. */
	if (PROTO_ITEM_IS_HIDDEN(node) && (prefs.display_hidden_proto_items == FALSE))
		return;

	/* Give up if we've already gotten an error. */
	if (!pdata->success)
		return;

	/* was a free format label produced? */
	if (fi->rep) {
		label_ptr = fi->rep->representation;
	}
	else { /* no, make a generic label */
		label_ptr = label_str;
		proto_item_fill_label(fi, label_str);
	}

	if (PROTO_ITEM_IS_GENERATED(node))
		label_ptr = g_strconcat("[", label_ptr, "]", NULL);

	pSimple_tree_node->name = g_strdup(label_ptr);
	pSimple_tree_node->abbrev = fi->hfinfo->abbrev;
	//pdata->success = print_line(pdata->stream, pdata->level, label_ptr);

	if (PROTO_ITEM_IS_GENERATED(node))
		g_free(label_ptr);

	/*if (!pdata->success)
		return;*/

		//will handle later*******************
		///* If it's uninterpreted data, dump it (unless our caller will
		//be printing the entire packet in hex). */
		//if ((fi->hfinfo->id == proto_data) && (pdata->print_hex_for_data)) {
		//	/*
		//	* Find the data for this field.
		//	*/
		//	pd = get_field_data(pdata->src_list, fi);
		//	if (pd) {
		//		if (!print_line(pdata->stream, 0, "")) {
		//			pdata->success = FALSE;
		//			return;
		//		}
		//		if (!print_hex_data_buffer(pdata->stream, pd,
		//			fi->length, pdata->encoding)) {
		//			pdata->success = FALSE;
		//			return;
		//		}
		//	}
		//}

		/* If we're printing all levels, or if this node is one with a
		subtree and its subtree is expanded, recurse into the subtree,
		if it exists. */
	g_assert((fi->tree_type >= -1) && (fi->tree_type < num_tree_types));
	//if ((fi->tree_type >= 0) && tree_expanded(fi->tree_type))
	{
		if (node->first_child != NULL)
		{
			pdata->level++;

			pSimple_tree_node->children = g_ptr_array_new();
			wz_proto_tree_children_foreach_frame_detail(pSimple_tree_node, node, pdata);
			pdata->level--;
			if (!pdata->success)
				return;
		}
	}
}
static void wz_proto_tree_children_foreach_frame_detail(wz_simple_treenode *pSimple_tree_node, proto_tree *tree, gpointer data)
{
	proto_node *node = tree;
	proto_node *current;

	if (!node)
		return;

	node = node->first_child;
	while (node != NULL) {
		current = node;
		node = current->next;

		wz_simple_treenode* pSimple_tree_node_child = malloc(sizeof(wz_simple_treenode));
		g_ptr_array_add(pSimple_tree_node->children, pSimple_tree_node_child);
		pSimple_tree_node_child->children = NULL;
		pSimple_tree_node_child->name = NULL;

		wz_proto_tree_print_node_detail(pSimple_tree_node_child, (proto_tree *)current, data);
	}
}
static gboolean wz_proto_tree_print_frame_detail(print_args_t *print_args, wz_LoadFileStatus *pLoadFileStatus)
{
	wz_print_data data;

	/* Create the output */
	data.level = 0;
	data.success = TRUE;
	data.src_list = pLoadFileStatus->edt->pi.data_src;
	data.encoding = (packet_char_enc)pLoadFileStatus->edt->pi.fd->encoding;
	data.print_dissections = print_args->print_dissections;
	/* If we're printing the entire packet in hex, don't
	print uninterpreted data fields in hex as well. */
	data.print_hex_for_data = !print_args->print_hex;
	//data.output_only_tables = output_only_tables;

	pLoadFileStatus->pLoadResult->pSimple_tree_node = malloc(sizeof(wz_simple_treenode));
	pLoadFileStatus->pLoadResult->pSimple_tree_node->name = NULL;
	pLoadFileStatus->pLoadResult->pSimple_tree_node->abbrev = NULL;
	pLoadFileStatus->pLoadResult->pSimple_tree_node->children = g_ptr_array_new();

	//get frame data
	GByteArray * bytes = g_byte_array_new();
	pLoadFileStatus->pLoadResult->pSimple_tree_node->abbrev = bytes;
	GSList *src_le;
	struct data_source *source;
	char* source_name;
	for (src_le = pLoadFileStatus->edt->pi.data_src; src_le != NULL; src_le = src_le->next)
	{
		source = (struct data_source *)src_le->data;
		tvbuff_t *tvb = get_data_source_tvb(source);
		guint tvb_len = tvb_captured_length(tvb);
		const guint8 *pd = tvb_get_ptr(tvb, 0, -1);
		g_byte_array_append(bytes, pd, tvb_len);
	}

	wz_proto_tree_children_foreach_frame_detail(pLoadFileStatus->pLoadResult->pSimple_tree_node, pLoadFileStatus->edt->tree, &data);
	return data.success;
}

static void get_frame_detail(wz_LoadFileStatus *pLoadFileStatus, frame_data* pFrame_data)
{
	print_args_t print_args;
	print_args.print_hex = print_hex;
	print_args.print_dissections = print_details ? print_dissections_expanded : print_dissections_none;

	if (!wz_proto_tree_print_frame_detail(&print_args, pLoadFileStatus))
		return FALSE;
	/*if (!print_hex) {
		if (!print_line(print_stream, 0, separator))
		return FALSE;
		print_hex_data(print_stream, pLoadFileStatus->edt);
		}*/
}
#pragma endregion

/* capture child detected an capture filter related error */
static void
capture_input_cfilter_error(capture_session* cap_session, guint i, const char* error_message)
{
	capture_options* capture_opts = cap_session->capture_opts;
	dfilter_t* rfcode = NULL;
	interface_options* interface_opts;

	ws_assert(i < capture_opts->ifaces->len);
	interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);

	if (dfilter_compile(interface_opts->cfilter, &rfcode, NULL) && rfcode != NULL) {
		cmdarg_err(
			"Invalid capture filter \"%s\" for interface '%s'.\n"
			"\n"
			"That string looks like a valid display filter; however, it isn't a valid\n"
			"capture filter (%s).\n"
			"\n"
			"Note that display filters and capture filters don't have the same syntax,\n"
			"so you can't use most display filter expressions as capture filters.\n"
			"\n"
			"See the User's Guide for a description of the capture filter syntax.",
			interface_opts->cfilter, interface_opts->descr, error_message);
		dfilter_free(rfcode);
	}
	else {
		cmdarg_err(
			"Invalid capture filter \"%s\" for interface '%s'.\n"
			"\n"
			"That string isn't a valid capture filter (%s).\n"
			"See the User's Guide for a description of the capture filter syntax.",
			interface_opts->cfilter, interface_opts->descr, error_message);
	}
}
static void capture_input_error(capture_session* cap_session,
	char* error_msg, char* secondary_error_msg);

int main(int argc, char *argv[])
{
	wz_Initialize("D:\\Projects\\zshark\\wsbuild64\\run\\RelWithDebInfo\\tshark.exe");
	wz_LoadResult* pLoadResult;

	pLoadParameters = malloc(sizeof(wz_LoadParameters));

	pLoadParameters->outputFlag = OUTPUT_FRAME_SUMMARY | OUTPUT_FIELD_VALUE;

	pLoadParameters->cf_name = "E:\\PCAP Samples\\Specific\\Web.pcap";
#pragma region frame detail
	pLoadParameters->outputFlag = OUTPUT_FRAME_DETAIL;
	//pLoadParameters->frameNumber = 10;
#pragma endregion 
#pragma region field value
	/*pLoadParameters->outputFlag = OUTPUT_FIELD_VALUE;
	pLoadParameters->fieldCount = 1;
	pLoadParameters->requestedFieldLoadFlags = malloc(sizeof(BYTE) * pLoadParameters->fieldCount);
	pLoadParameters->requestedFieldLoadFlags[0] = 1;
	char* outFields[] = { "tcp.srcport" };
	pLoadParameters->requestedFields = &outFields[0];*/
#pragma region 
	pLoadResult = wz_LoadPcapFile(pLoadParameters);

	wz_Free_LoadResult(pLoadResult);
	wz_Free_EntireWiresharkResource();
}
int wz_Initialize(char* szDllDir)
{
	GString             *comp_info_str;
	GString             *runtime_info_str;
	char                *init_progfile_dir_error;
	int                  opt;
	static const struct ws_option long_options[] = {
			{ "help", ws_no_argument, NULL, 'h' },
			{ "version", ws_no_argument, NULL, 'v' },
			{ 0, 0, 0, 0 }
	};
	gboolean             arg_error = FALSE;

	int                  err;
	volatile int         exit_status = 0;
#ifdef HAVE_LIBPCAP
	gboolean             list_link_layer_types = FALSE;
	gboolean             start_capture = FALSE;
	int                  status;
	GList               *if_list;
	gchar               *err_str;
#else
	gboolean             capture_option_specified = FALSE;
#endif
	gboolean             quiet = FALSE;
#ifdef PCAP_NG_DEFAULT
	volatile int         out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;
#else
	volatile int         out_file_type = WTAP_FILE_TYPE_SUBTYPE_UNKNOWN;
#endif
	volatile gboolean    out_file_name_res = FALSE;
	volatile int         in_file_type = WTAP_TYPE_AUTO;
	gchar               *volatile cf_name = NULL;
	gchar               *rfilter = NULL;
	gchar               *dfilter = NULL;
#ifdef HAVE_PCAP_OPEN_DEAD
	struct bpf_program   fcode;
#endif
	dfilter_t           *rfcode = NULL;
	dfilter_t           *dfcode = NULL;
	gchar               *err_msg;
	e_prefs             *prefs_p;
	char                 badopt;
	int                  log_flags;
	gchar               *output_only = NULL;
	gchar               *volatile pdu_export_arg = NULL;
	exp_pdu_t            exp_pdu_tap_data;

	int argc = 7;
	char* argv[] = {
		"D:\\Projects\\zshark\\wsbuild64\\run\\RelWithDebInfo\\tshark.exe",
		"-r",
		"D:\\Projects\\zshark\\wsbuild64\\run\\RelWithDebInfo\\Web.pcap",
		"-T",
		"fields",
		"-e",
		"<tcp.stream, tcp.port>"
	};

	/*
	* The leading + ensures that getopt_long() does not permute the argv[]
	* entries.
	*
	* We have to make sure that the first getopt_long() preserves the content
	* of argv[] for the subsequent getopt_long() call.
	*
	* We use getopt_long() in both cases to ensure that we're using a routine
	* whose permutation behavior we can control in the same fashion on all
	* platforms, and so that, if we ever need to process a long argument before
	* doing further initialization, we can do so.
	*
	* Glibc and Solaris libc document that a leading + disables permutation
	* of options, regardless of whether POSIXLY_CORRECT is set or not; *BSD
	* and OS X don't document it, but do so anyway.
	*
	* We do *not* use a leading - because the behavior of a leading - is
	* platform-dependent.
	*/
#define OPTSTRING "+2" OPTSTRING_CAPTURE_COMMON "C:d:e:E:F:gG:hH:j:" "K:lnN:o:O:PqQr:R:S:t:T:u:U:vVw:W:xX:Y:z:"

	static const char    optstring[] = OPTSTRING;

	tshark_debug("tshark started with %d args", argc);

	/* Set the C-language locale to the native environment. */
	setlocale(LC_ALL, "");

	cmdarg_err_init(failure_message, failure_message_cont);

#ifdef _WIN32
	arg_list_utf_16to8(argc, argv);
	//create_app_running_mutex();
#if !GLIB_CHECK_VERSION(2,31,0)
	g_thread_init(NULL);
#endif
#endif /* _WIN32 */

	/*
	* Get credential information for later use, and drop privileges
	* before doing anything else.
	* Let the user know if anything happened.capture_input_new_packets
	*/
	init_process_policies();
	relinquish_special_privs_perm();
	print_current_user();

	/*
	* Attempt to get the pathname of the directory containing the
	* executable file.
	*/
	init_progfile_dir_error = configuration_init(szDllDir, NULL);
	/*if (init_progfile_dir_error != NULL) {
		fprintf(stderr,
			"tshark: Can't get pathname of directory containing the tshark program: %s.\n"
			"It won't be possible to capture traffic.\n"
			"Report this to the Wireshark developers.",
			init_progfile_dir_error);
		g_free(init_progfile_dir_error);
	}*/

	initialize_funnel_ops();

#ifdef _WIN32
	ws_init_dll_search_path();
	/* Load wpcap if possible. Do this before collecting the run-time version information */
	load_wpcap();

	///* Warn the user if npf.sys isn't loaded. */
	//if (!npf_sys_is_running() && get_windows_major_version() >= 6) {
	//	fprintf(stderr, "The NPF driver isn't running.  You may have trouble "
	//		"capturing or\nlisting interfaces.\n");
	//}
#endif


	///* Get the compile-time version information string */
	//comp_info_str = get_compiled_version_info(get_tshark_compiled_version_info);

	///* Get the run-time version information string */
	//runtime_info_str = get_runtime_version_info(get_tshark_runtime_version_info);

	///* Add it to the information to be reported on a crash. */
	//ws_add_crash_info("TShark (Wireshark) %s\n"
	//	"\n"
	//	"%s"
	//	"\n"
	//	"%s",
	//	get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);
	//g_string_free(comp_info_str, TRUE);
	//g_string_free(runtime_info_str, TRUE);

	/* Fail sometimes. Useful for testing fuzz scripts. */
	/* if (g_random_int_range(0, 100) < 5) abort(); */

	/*
	* In order to have the -X opts assigned before the wslua machine starts
	* we need to call getopt_long before epan_init() gets called.
	*
	* In order to handle, for example, -o options, we also need to call it
	* *after* epan_init() gets called, so that the dissectors have had a
	* chance to register their preferences.
	*
	* XXX - can we do this all with one getopt_long() call, saving the
	* arguments we can't handle until after initializing libwireshark,
	* and then process them after initializing libwireshark?
	*/
	ws_opterr = 0;

	while ((opt = ws_getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (opt) {
		case 'C':        /* Configuration Profile */
			if (profile_exists(ws_optarg, FALSE)) {
				set_profile_name(ws_optarg);
			}
			else {
				cmdarg_err("Configuration Profile \"%s\" does not exist", ws_optarg);
				return 1;
			}
			break;
		case 'P':        /* Print packet summary info even when writing to a file */
			print_packet_info = TRUE;
			print_summary = TRUE;
			break;
		case 'O':        /* Only output these protocols */
			output_only = g_strdup(ws_optarg);
			/* FALLTHROUGH */
		case 'V':        /* Verbose */
			print_details = TRUE;
			print_packet_info = TRUE;
			break;
		case 'x':        /* Print packet data in hex (and ASCII) */
			print_hex = TRUE;
			/*  The user asked for hex output, so let's ensure they get it,
			*  even if they're writing to a file.
			*/
			print_packet_info = TRUE;
			break;
		case 'X':
			ex_opt_add(ws_optarg);
			break;
		default:
			break;
		}
	}

	/*
	* Print packet summary information is the default, unless either -V or -x
	* were specified and -P was not.  Note that this is new behavior, which
	* allows for the possibility of printing only hex/ascii output without
	* necessarily requiring that either the summary or details be printed too.
	*/
	if (print_summary == -1)
		print_summary = (print_details || print_hex) ? FALSE : TRUE;

	/** Send All g_log messages to our own handler **/

	log_flags =
		G_LOG_LEVEL_ERROR |
		G_LOG_LEVEL_CRITICAL |
		G_LOG_LEVEL_WARNING |
		G_LOG_LEVEL_MESSAGE |
		G_LOG_LEVEL_INFO |
		G_LOG_LEVEL_DEBUG |
		G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION;

	g_log_set_handler(NULL,
		(GLogLevelFlags)log_flags,
		tshark_log_handler, NULL /* user_data */);
	g_log_set_handler(LOG_DOMAIN_MAIN,
		(GLogLevelFlags)log_flags,
		tshark_log_handler, NULL /* user_data */);

#ifdef HAVE_LIBPCAP
	capture_opts_init(&global_capture_opts);
	capture_session_init(&global_capture_session, &cfile,
		capture_input_new_file, capture_input_new_packets,
		capture_input_drops, capture_input_error,
		capture_input_cfilter_error, capture_input_closed);
#endif

	/*init_report_err(failure_message, open_failure_message, read_failure_message,
		write_failure_message);*/

	timestamp_set_type(TS_RELATIVE);
	timestamp_set_precision(TS_PREC_AUTO);
	timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

	wtap_init(TRUE);

	/* Register all dissectors; we must do this before checking for the
	"-G" flag, as the "-G" flag dumps information registered by the
	dissectors, and we must do it before we read the preferences, in
	case any dissectors register preferences. */
	if (!epan_init(NULL, NULL, TRUE))
		return 2;

	/* Register all tap listeners; we do this before we parse the arguments,
	as the "-z" argument can specify a registered tap. */

	int                  gpf_open_errno, gpf_read_errno;
	int                  pf_open_errno, pf_read_errno;
	int                  gdp_open_errno, gdp_read_errno;
	char                *gpf_path, *pf_path;
	char                *gdp_path, *dp_path;
	char*				errInfo = NULL;
	gchar*				err_info = NULL;
	loadFileStatus.prefs_p = epan_load_settings();
	//if (gpf_path != NULL) {
	//	if (gpf_open_errno != 0) {
	//		sprintf(errInfo, "Can't open global preferences file \"%s\": %s.",
	//			pf_path, g_strerror(gpf_open_errno));
	//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
	//	}
	//	if (gpf_read_errno != 0) {
	//		sprintf(errInfo, "I/O error reading global preferences file \"%s\": %s.",
	//			pf_path, g_strerror(gpf_read_errno));
	//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
	//	}
	//}
	//if (pf_path != NULL) {
	//	if (pf_open_errno != 0) {
	//		sprintf(errInfo, "Can't open your preferences file \"%s\": %s.", pf_path,
	//			g_strerror(pf_open_errno));
	//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
	//	}
	//	if (pf_read_errno != 0) {
	//		sprintf(errInfo, "I/O error reading your preferences file \"%s\": %s.",
	//			pf_path, g_strerror(pf_read_errno));
	//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
	//	}
	//	g_free(pf_path);
	//	pf_path = NULL;
	//}
	/* Notify all registered modules that have had any of their preferences
	changed either from one of the preferences file or from the command
	line that their preferences have changed. */
	prefs_apply_all();

#ifdef HAVE_EXTCAP
	extcap_register_preferences();
#endif
}
static void wz_prepare_LoadResult(wz_LoadFileStatus* pLoadFileStatus)
{
	memset(pLoadFileStatus->pLoadResult, 0, sizeof(wz_LoadResult));
	if (pLoadParameters->outputFlag & OUTPUT_FIELD_VALUE)
#pragma region
	{
		//pLoadFileStatus->pLoadResult->FrameInfo = g_new(GArray*, FrameInfoCount); //index,time
		//pLoadFileStatus->pLoadResult->FrameInfo[0] = g_array_new(FALSE, FALSE, sizeof(UINT32)); //index
		//pLoadFileStatus->pLoadResult->FrameInfo[1] = g_array_new(FALSE, FALSE, sizeof(double));//(guint64)timestamp->secs, timestamp->nsecs/1000000000

		guint fieldCount = pLoadFileStatus->output_fields.fields->len;
		pLoadFileStatus->pLoadResult->FrameIndexInsteadOfTime = pLoadParameters->FrameIndexInsteadOfTime;
		pLoadFileStatus->pLoadResult->FieldCount = fieldCount;

		pLoadFileStatus->pLoadResult->output_field_ftype = malloc(sizeof(ftenum_t)* fieldCount);

		pLoadFileStatus->pLoadResult->FieldDataArrays = g_new0(GArray*, fieldCount);
		pLoadFileStatus->pLoadResult->FieldIndexArrays = g_new0(GArray*, fieldCount);
		pLoadFileStatus->pLoadResult->FieldNeedIndexArray = (guint8*)malloc(sizeof(guint8)*fieldCount);
		pLoadFileStatus->pLoadResult->FieldNeedSaved = (guint8*)malloc(sizeof(guint8)*fieldCount);

		/*determine if some fields are in the same protocol and so no need to*/
		int iProtocolNameSize = 0;
		gchar* pFieldNameLast = NULL;
		gchar* pFieldName = NULL;
		for (int m = 0; m < fieldCount; ++m)
		{
			pLoadFileStatus->pLoadResult->FieldNeedIndexArray[m] = 1; //init to 1

			pFieldName = g_ptr_array_index(pLoadFileStatus->output_fields.fields, m);

			if (iProtocolNameSize > 0)
			{
				if (strncmp(pFieldNameLast, pFieldName, iProtocolNameSize) == 0)
				{
					pLoadFileStatus->pLoadResult->FieldNeedIndexArray[m] = 0;
					continue;
				}
				else

					iProtocolNameSize = 0; //start a new protocol
			}

			if (iProtocolNameSize == 0)
			{
				char* pFound = strchr(pFieldName, '.');
				if (pFound != NULL)
				{
					iProtocolNameSize = pFound - pFieldName + 1; //include "."
					pFieldNameLast = pFieldName;
				}
			}
		}
	}
#pragma endregion
	else
	{
		pLoadFileStatus->pLoadResult->FieldCount = 0;
	}
	
}

static char* InterpolateError(int err, gchar* err_info)
{
	char* errInfo = NULL;
	switch (err)
	{
#pragma region
	case 0: break;
	case WTAP_ERR_UNSUPPORTED:
		sprintf(errInfo, "The file \"%s\" contains record data that TShark doesn't support.\n(%s)",
			loadFileStatus.cfile.filename,
			err_info != NULL ? err_info : "no information supplied");
		break;

	case WTAP_ERR_SHORT_READ:
		sprintf(errInfo, "The file \"%s\" appears to have been cut short in the middle of a packet.",
			loadFileStatus.cfile.filename);
		break;

	case WTAP_ERR_BAD_FILE:
		sprintf(errInfo, "The file \"%s\" appears to be damaged or corrupt.\n(%s)",
			loadFileStatus.cfile.filename,
			err_info != NULL ? err_info : "no information supplied");
		break;

	case WTAP_ERR_DECOMPRESS:
		sprintf(errInfo, "The compressed file \"%s\" appears to be damaged or corrupt.\n"
			"(%s)", loadFileStatus.cfile.filename,
			err_info != NULL ? err_info : "no information supplied");
		break;

	default:
		sprintf(errInfo, "An error occurred while reading the file \"%s\": %s.",
			loadFileStatus.cfile.filename, wtap_strerror(err));
		break;
#pragma endregion
	}
	return errInfo;
}
static gboolean wz_process_packet(wz_LoadFileStatus *pLoadFileStatus,
	wtap_rec* rec, Buffer* buf)
{
	frame_data      fdata;
	column_info    *cinfo;
	gboolean        passed;

	/* Count this packet. */
	pLoadFileStatus->cfile.count++;

	/* If we're not running a display filter and we're not printing any
	packet information, we don't need to do a dissection. This means
	that all packets can be marked as 'passed'. */
	passed = TRUE;

	frame_data_init(&fdata, pLoadFileStatus->cfile.count, rec, pLoadFileStatus->data_offset, cum_bytes);

	/* If we're going to print packet information, or we're going to
	run a read filter, or we're going to process taps, set up to
	do a dissection and do so. */
	if (pLoadFileStatus->edt) {
		if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
			gbl_resolv_flags.transport_name)
			/* Grab any resolved addresses */
			host_name_lookup_process();

		/* If we're running a filter, prime the epan_dissect_t with that
		filter. */
		if (cfile.dfcode)
			epan_dissect_prime_with_dfilter(pLoadFileStatus->edt, pLoadFileStatus->cfile.dfcode);

		col_custom_prime_edt(pLoadFileStatus->edt, &pLoadFileStatus->cfile.cinfo);

		/* We only need the columns if either
		1) some tap needs the columns
		or
		2) we're printing packet info but we're *not* verbose; in verbose
		mode, we print the protocol tree, not the protocol summary.
		or
		3) there is a column mapped as an individual field */
		if ((pLoadFileStatus->tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary)
			|| pLoadFileStatus->output_fields.includes_col_fields)
			cinfo = &pLoadFileStatus->cfile.cinfo;
		else
			cinfo = NULL;

		frame_data_set_before_dissect(&fdata, &pLoadFileStatus->cfile.elapsed_time,
			&ref, prev_dis);
		if (ref == &fdata) {
			ref_frame = fdata;
			ref = &ref_frame;
		}
		epan_dissect_run_with_taps(pLoadFileStatus->edt, pLoadFileStatus->cfile.cd_t, rec,
			frame_tvbuff_new_buffer(&pLoadFileStatus->cfile.provider, &fdata, buf), &fdata, cinfo);

		/* Run the filter if we have it. */
		if (pLoadFileStatus->cfile.dfcode)
			passed = dfilter_apply_edt(pLoadFileStatus->cfile.dfcode, pLoadFileStatus->edt);
	}

	if (passed) {
		frame_data_set_after_dissect(&fdata, &cum_bytes);

		if (pLoadParameters->outputFlag & OUTPUT_FRAME_SUMMARY)
			get_frame_list(pLoadFileStatus, &fdata);

		if (pLoadParameters->outputFlag & OUTPUT_FIELD_VALUE)
			get_specified_fields(pLoadFileStatus, &fdata);

		if (pLoadParameters->outputFlag & OUTPUT_FRAME_DETAIL)
		{
			//if (pLoadFileStatus->cfile.count == pLoadParameters->frameNumber)
				get_frame_detail(pLoadFileStatus, &fdata);
		}

		/* this must be set after print_packet() [bug #8160] */
		prev_dis_frame = fdata;
		prev_dis = &prev_dis_frame;
	}

	prev_cap_frame = fdata;
	prev_cap = &prev_cap_frame;

	if (pLoadFileStatus->edt) {
		epan_dissect_reset(pLoadFileStatus->edt);
		frame_data_destroy(&fdata);
	}
	return passed;
}
gboolean process_packet_second_pass(wz_LoadFileStatus *pLoadFileStatus, frame_data *fdata, struct wtap_pkthdr *phdr, Buffer *buf)
{
	column_info    *cinfo;
	gboolean        passed;

	/* If we're not running a display filter and we're not printing any
	packet information, we don't need to do a dissection. This means
	that all packets can be marked as 'passed'. */
	passed = TRUE;

	/* If we're going to print packet information, or we're going to
	run a read filter, or we're going to process taps, set up to
	do a dissection and do so. */
	if (pLoadFileStatus->edt) {
		if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
			gbl_resolv_flags.transport_name)
			/* Grab any resolved addresses */
			host_name_lookup_process();

		/* If we're running a display filter, prime the epan_dissect_t with that
		filter. */
		if (pLoadFileStatus->cfile.dfcode)
			epan_dissect_prime_with_dfilter(pLoadFileStatus->edt, pLoadFileStatus->cfile.dfcode);

		col_custom_prime_edt(pLoadFileStatus->edt, &pLoadFileStatus->cfile.cinfo);

		/* We only need the columns if either
		1) some tap needs the columns
		or
		2) we're printing packet info but we're *not* verbose; in verbose
		mode, we print the protocol tree, not the protocol summary.
		*/
		if ((pLoadFileStatus->tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary)
			|| pLoadFileStatus->output_fields.includes_col_fields)
			cinfo = &pLoadFileStatus->cfile.cinfo;
		else
			cinfo = NULL;

		frame_data_set_before_dissect(fdata, &pLoadFileStatus->cfile.elapsed_time,
			&ref, prev_dis);
		if (ref == fdata) {
			ref_frame = *fdata;
			ref = &ref_frame;
		}

		epan_dissect_run_with_taps(pLoadFileStatus->edt, pLoadFileStatus->cfile.cd_t, phdr, 
			frame_tvbuff_new_buffer(&pLoadFileStatus->cfile.provider, fdata, buf), fdata, cinfo);

		/* Run the read/display filter if we have one. */
		if (pLoadFileStatus->cfile.dfcode)
			passed = dfilter_apply_edt(pLoadFileStatus->cfile.dfcode, pLoadFileStatus->edt);
	}

	if (passed) {
		frame_data_set_after_dissect(fdata, &cum_bytes);

		get_specified_fields(pLoadFileStatus, &fdata);
		prev_dis = fdata;
	}
	prev_cap = fdata;

	if (pLoadFileStatus->edt) {
		epan_dissect_reset(pLoadFileStatus->edt);
	}
	return passed || fdata->dependent_of_displayed;
}

void wz_InitLoadFileStatus()
{
	loadFileStatus.pLoadResult = (wz_LoadResult*)malloc(sizeof(wz_LoadResult));
	loadFileStatus.pLoadResult->errorInfo = g_ptr_array_new();

	loadFileStatus.edt = NULL;
	//loadFileStatus.prefs_p = NULL;
	loadFileStatus.output_fieldLoadFlags = NULL;
	wz_output_fields_new(&loadFileStatus.output_fields);

	loadFileStatus.pLoadResult->pSimple_tree_node = NULL;
}
wz_LoadResult* wz_LoadPcapFile(wz_LoadParameters* loadParameters)
{
	__try
	{
		volatile int         in_file_type = WTAP_TYPE_AUTO;
		char* cf_path;
		int                  dp_open_errno, dp_read_errno;
		int                  cf_open_errno;
		GSList* disable_protocol_slist = NULL;
		GSList* enable_heur_slist = NULL;
		GSList* disable_heur_slist = NULL;
		char* errInfo = NULL;
		gchar* err_info = NULL;

		pLoadParameters = loadParameters;

		/* load the decode as entries of this profile */
		//load_decode_as_entries();
		wz_InitLoadFileStatus();

		print_packet_info = print_summary = print_details = FALSE;
		if (pLoadParameters->outputFlag & OUTPUT_FRAME_SUMMARY)
		{
			print_packet_info = TRUE;
			print_summary = TRUE;
		}
		if (pLoadParameters->outputFlag & OUTPUT_FRAME_DETAIL)
		{
			print_details = TRUE;
			print_packet_info = TRUE;
		}
#pragma region read error checking
		int                  gpf_open_errno, gpf_read_errno;
		int                  pf_open_errno, pf_read_errno;
		int                  gdp_open_errno, gdp_read_errno;
		char* gpf_path, * pf_path;
		char* gdp_path, * dp_path;

		loadFileStatus.prefs_p = epan_load_settings();
		read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);
		if (cf_path != NULL) {
			/*sprintf(errInfo, "Could not open your capture filter file\n\"%s\": %s.",
				cf_path, g_strerror(cf_open_errno));
			g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
			g_free(cf_path);*/
		}

		///* Read the disabled protocols file. */
		//read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
		//	&dp_path, &dp_open_errno, &dp_read_errno);
		//read_disabled_heur_dissector_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
		//	&dp_path, &dp_open_errno, &dp_read_errno);
		//if (gdp_path != NULL) {
		//	if (gdp_open_errno != 0) {
		//		sprintf(errInfo, "Could not open global disabled protocols file\n\"%s\": %s.",
		//			gdp_path, g_strerror(gdp_open_errno));
		//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
		//	}
		//	if (gdp_read_errno != 0) {
		//		sprintf(errInfo, "I/O error reading global disabled protocols file\n\"%s\": %s.",
		//			gdp_path, g_strerror(gdp_read_errno));
		//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
		//	}
		//	g_free(gdp_path);
		//}
		//if (dp_path != NULL) {
		//	if (dp_open_errno != 0) {
		//		sprintf(errInfo, "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
		//			g_strerror(dp_open_errno));
		//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
		//	}
		//	if (dp_read_errno != 0) {
		//		sprintf(errInfo, "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
		//			g_strerror(dp_read_errno));
		//		g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
		//	}
		//	g_free(dp_path);
		//}
#pragma endregion

		/*
		* To reset the options parser, set optreset to 1 on platforms that
		* have optreset (documented in *BSD and OS X, apparently present but
		* not documented in Solaris - the Illumos repository seems to
		* suggest that the first Solaris getopt_long(), at least as of 2004,
		* was based on the NetBSD one, it had optreset) and set optind to 1,
		* and set optind to 0 otherwise (documented as working in the GNU
		* getopt_long().  Setting optind to 0 didn't originally work in the
		* NetBSD one, but that was added later - we don't want to depend on
		* it if we have optreset).
		*
		* Also reset opterr to 1, so that error messages are printed by
		* getopt_long().
		*/
#pragma region disabled protocols as per configuration file 
		if (gdp_path == NULL && dp_path == NULL) {
			//set_disabled_protos_list();
			//set_disabled_heur_dissector_list();
		}

		if (disable_protocol_slist) {
			GSList* proto_disable;
			for (proto_disable = disable_protocol_slist; proto_disable != NULL; proto_disable = g_slist_next(proto_disable))
			{
				proto_disable_proto_by_name((char*)proto_disable->data);
			}
		}

		if (enable_heur_slist) {
			GSList* heur_enable;
			for (heur_enable = enable_heur_slist; heur_enable != NULL; heur_enable = g_slist_next(heur_enable))
			{
				proto_enable_heuristic_by_name((char*)heur_enable->data, TRUE);
			}
		}

		if (disable_heur_slist) {
			GSList* heur_disable;
			for (heur_disable = disable_heur_slist; heur_disable != NULL; heur_disable = g_slist_next(heur_disable))
			{
				proto_enable_heuristic_by_name((char*)heur_disable->data, FALSE);
			}
		}
#pragma endregion 

		/*do_dissection = print_packet_info || rfcode || dfcode || pdu_export_arg ||
			tap_listeners_require_dissection();*/
		gchar* err_msg;
		dfilter_t* rfcode = NULL;
		if (pLoadParameters->filter != NULL)
		{
			if (!dfilter_compile(pLoadParameters->filter, &rfcode, &err_msg))
			{
				return;
			}
		}
		int err;
		cap_file_init(&loadFileStatus.cfile);
		loadFileStatus.cfile.rfcode = rfcode;

		if (cf_open(&loadFileStatus.cfile, pLoadParameters->cf_name, in_file_type, FALSE, &err) != CF_OK)
			return NULL;

		perform_two_pass_analysis = true;
		loadFileStatus.edt = NULL;

		loadFileStatus.linktype = wtap_file_encap(loadFileStatus.cfile.provider.wth);

		/* Do we have any tap listeners with filters? */
		loadFileStatus.filtering_tap_listeners = have_filtering_tap_listeners();
		/* Get the union of the flags for all tap listeners. */
		loadFileStatus.tap_flags = union_of_tap_listener_flags();

		/* !perform_two_pass_analysis */
		loadFileStatus.frameIndex = 0;

		/*if (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
			(tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
			create_proto_tree = TRUE;
			else
			create_proto_tree = FALSE;*/

		gboolean create_proto_tree = pLoadParameters->ShallCreateProtocolTree > 0;  //in some cases, it should be FALSE, need more study
		/* The protocol tree will be "visible", i.e., printed, only if we're
		printing packet details, which is true if we're printing stuff
		("print_packet_info" is true) and we're in verbose mode
		("packet_details" is true). */
		loadFileStatus.edt = epan_dissect_new(loadFileStatus.cfile.epan, create_proto_tree,
			(pLoadParameters->outputFlag & OUTPUT_FIELD_VALUE) || (pLoadParameters->outputFlag & OUTPUT_FRAME_DETAIL));

		/* Build the column format array */
		build_column_format_array(&loadFileStatus.cfile.cinfo, loadFileStatus.prefs_p->num_cols, TRUE);

		if (pLoadParameters->outputFlag & OUTPUT_FIELD_VALUE)
		{
			for (int m = 0; m < pLoadParameters->fieldCount; ++m)
				wz_output_fields_add(&loadFileStatus.output_fields, pLoadParameters->requestedFields[m]);
		}
		/*prepare data structure for data output*/
		wz_prepare_LoadResult(&loadFileStatus, pLoadParameters);

		gboolean getVoIPCalls = FALSE;		
		if (pLoadParameters->outputFlag & OUTPUT_FIELD_VALUE)
#pragma region
		{
			//peter move up before wz_prepare_LoadResult()
			/*for (int m = 0; m < pLoadParameters->fieldCount; ++m)
				wz_output_fields_add(&loadFileStatus.output_fields, pLoadParameters->requestedFields[m]);*/

				/* At this point MATE will have registered its field array so we can
				check if the fields specified by the user are all good.
				*/
			{
				GSList* it = NULL;
				GSList* invalid_fields = output_fields_valid(&loadFileStatus.output_fields);
				if (invalid_fields != NULL) {

					/*errInfo = "Some fields aren't valid:";
					g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);

					for (it = invalid_fields; it != NULL; it = g_slist_next(it)) {
						sprintf(errInfo, "\t%s", (gchar*)it->data);
						g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);
					}*/
					g_slist_free(invalid_fields);
					return 1;
				}
			}
			loadFileStatus.output_fieldLoadFlags = pLoadParameters->requestedFieldLoadFlags;
			loadFileStatus.output_fields.field_values = g_new0(gpointer, loadFileStatus.output_fields.fields->len);
			/* Prepare a lookup table from string abbreviation for field to its index. */
			loadFileStatus.output_fields.field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

			int i = 0;
			while (i < loadFileStatus.output_fields.fields->len) {
				gchar* field = (gchar*)g_ptr_array_index(loadFileStatus.output_fields.fields, i);
				/* Store field indicies +1 so that zero is not a valid value,
				* and can be distinguished from NULL as a pointer.
				*/
				++i;
				g_hash_table_insert(loadFileStatus.output_fields.field_indicies, field, GUINT_TO_POINTER(i));
			}
		}
#pragma endregion

		reset_tap_listeners();
		wtap_rec        rec;
		Buffer          buf;
		wtap_rec_init(&rec);
		ws_buffer_init(&buf, 1514);

		if (pLoadParameters->outputFlag & OUTPUT_FRAME_DETAIL)
		{
			wtap_seek_read(loadFileStatus.cfile.provider.wth, pLoadParameters->filePosition, &rec, &buf, &err, &err_info);
			wz_process_packet(&loadFileStatus, &rec, &buf);
		}
		else
		{
			while (wtap_read(loadFileStatus.cfile.provider.wth, &rec, &buf, &err, &err_info, &loadFileStatus.data_offset))
			{
				wz_process_packet(&loadFileStatus, &rec, &buf);
				loadFileStatus.frameIndex++;

				/*if (pLoadParameters->outputFlag & OUTPUT_FRAME_DETAIL)
				{
					if (loadFileStatus.frameIndex >= pLoadParameters->frameNumber)
						break;
				}*/
			}
		}

		/*errInfo = InterpolateError(err, err_info);
		if (errInfo != NULL)
			g_array_append_val(loadFileStatus.pLoadResult->errorInfo, errInfo);*/

		wtap_close(loadFileStatus.cfile.provider.wth);
		loadFileStatus.cfile.provider.wth = NULL;

		if (loadFileStatus.cfile.provider.frames != NULL) {
			free_frame_data_sequence(loadFileStatus.cfile.provider.frames);
			loadFileStatus.cfile.provider.frames = NULL;
		}
			
		draw_tap_listeners(TRUE); //dump stat data
		epan_free(loadFileStatus.cfile.epan);

		g_ptr_array_free(loadFileStatus.output_fields.fields, TRUE);
		g_free(loadFileStatus.output_fields.field_values);
		g_hash_table_destroy(loadFileStatus.output_fields.field_indicies);

		return loadFileStatus.pLoadResult;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{		
	}

	return NULL;
}
char* wz_address_to_str(address *addr, int resolveName)
{
	if (resolveName > 0)
		return (char*)address_to_display(NULL, addr);
	return (char*)address_to_str(NULL, addr);
}
#pragma region Free resource
void wz_G_Free(void* pData)
{
	g_free(pData);
}
void wz_g_byte_array_free(void* pData)
{
	g_byte_array_free(pData, TRUE);
}
void wz_g_ptr_array_free(void* pData)
{
	g_ptr_array_free(pData, TRUE);
}
void wz_Free_LoadResultOfField(wz_LoadResult* pLoadResult, int fieldIndex)
{
	if (pLoadResult == NULL)
		return;

	if (pLoadResult->FieldDataArrays != NULL && fieldIndex < pLoadResult->FieldCount)
	{
		g_array_free(pLoadResult->FieldDataArrays[fieldIndex], TRUE);
		pLoadResult->FieldDataArrays[fieldIndex] = NULL;
		g_array_free(pLoadResult->FieldIndexArrays[fieldIndex], TRUE);
		pLoadResult->FieldIndexArrays[fieldIndex] = NULL;
	}
}
void wz_Free_LoadResult(wz_LoadResult* pLoadResult)
{
	if (pLoadResult == NULL)
		return;

	if (pLoadResult->errorInfo != NULL)
		g_array_free(pLoadResult->errorInfo, TRUE);

	if (pLoadResult->FieldCount != NULL)
	{
		//field data
		for (int i = 0; i < pLoadResult->FieldCount; ++i)
		{
			if (pLoadResult->FieldDataArrays[i] != NULL)
				g_array_free(pLoadResult->FieldDataArrays[i], TRUE);
			if (pLoadResult->FieldIndexArrays[i] != NULL)
				g_array_free(pLoadResult->FieldIndexArrays[i], TRUE);
		}
		g_free(pLoadResult->FieldDataArrays);
		g_free(pLoadResult->FieldIndexArrays);
		free(pLoadResult->output_field_ftype);

		////frame data
		//for (int m = 0; m < FrameInfoCount; ++m)
		//	g_array_free(pLoadResult->FrameInfo[m], TRUE);
		//g_free(pLoadResult->FrameInfo);
	}
	
	if (pLoadResult->FrameSummary != NULL)
		g_ptr_array_free(pLoadResult->FrameSummary, TRUE);

	//free the entire tree during zeePoint
	//if (pLoadResult->Stat_ProtocolHierarchy!= NULL)
	//	g_free(pLoadResult->Stat_ProtocolHierarchy);

	free(pLoadResult);
}
void wz_Free_EntireWiresharkResource(void)
{
	epan_cleanup();
#ifdef HAVE_EXTCAP
	extcap_cleanup();
#endif
}
#pragma endregion
#pragma region Get protocol structure
char ** wz_GetProtocolFieldNames(int* arrayLength)
{
	int totalCount = 0;
	char **fieldArray;
	void *proto_cookie;
	void *field_cookie;
	int checkIsLayer3 = 0;

	for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
		proto_id = proto_get_next_protocol(&proto_cookie))
	{
		protocol_t *protocol = find_protocol_by_id(proto_id);
		//if (!proto_is_protocol_enabled(protocol))
		//	continue;

		totalCount += 3; //insert empty string in front of it
		checkIsLayer3 = wz_IsLayer3(proto_get_protocol_short_name(protocol));
		for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL;
			hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie))
		{
			if (hfinfo->same_name_prev_id != -1)
				continue; // Ignore duplicate names.

			totalCount += checkIsLayer3 == 1 ? 1 : 2;
		}
	}

	*arrayLength = totalCount;
	fieldArray = malloc(totalCount * sizeof(char*));
	totalCount = 0;
	for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
		proto_id = proto_get_next_protocol(&proto_cookie))
	{
		protocol_t *protocol = find_protocol_by_id(proto_id);
		//if (!proto_is_protocol_enabled(protocol))
		//	continue;

		fieldArray[totalCount++] = "";

		fieldArray[totalCount] = proto_get_protocol_short_name(protocol);
		checkIsLayer3 = wz_IsLayer3(fieldArray[totalCount]);

		totalCount++;
		fieldArray[totalCount++] = proto_get_protocol_long_name(protocol);


		for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo != NULL;
			hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie))
		{
			if (hfinfo->same_name_prev_id != -1)
				continue; // Ignore duplicate names.

			fieldArray[totalCount++] = hfinfo->abbrev;
			if (checkIsLayer3 != 1)
				fieldArray[totalCount++] = hfinfo->name;
		}
	}
	return fieldArray;
}
int wz_IsLayer3(char* szShortName)
{
	return strcmp(szShortName, "RRC") == 0
		|| strcmp(szShortName, "RRLP") == 0
		|| strcmp(szShortName, "HNBAP") == 0
		|| strcmp(szShortName, "LPP") == 0
		|| strcmp(szShortName, "M2AP") == 0
		|| strcmp(szShortName, "M3AP") == 0
		|| strcmp(szShortName, "NBAP") == 0
		|| strcmp(szShortName, "RANAP") == 0
		|| strcmp(szShortName, "RNSAP") == 0
		|| strcmp(szShortName, "RUA") == 0
		|| strcmp(szShortName, "S1AP") == 0
		|| strcmp(szShortName, "SABP") == 0
		|| strcmp(szShortName, "SNMP") == 0
		|| strcmp(szShortName, "X2AP") == 0 ? 1 : 0;
}
void wz_Free_GetProtocolFieldNames(char ** pointer)
{
	free(pointer);
}
#pragma endregion
#pragma region preference
static guint pref_exists(pref_t * a, gpointer b)
{
	return 1;
}
guint
pref_stash(wz_pref_t* pref, gpointer unused _U_)
{
	switch (pref->type) {

	case PREF_DECODE_AS_UINT:
		pref->stashed_val.uint = *pref->varp.uint;
		break;

	case PREF_UINT:
		pref->stashed_val.uint = *pref->varp.uint;
		break;

	case PREF_BOOL:
		pref->stashed_val.boolval = *pref->varp.boolp;
		break;

	case PREF_ENUM:
		pref->stashed_val.enumval = *pref->varp.enump;
		break;

	case PREF_STRING:
	case PREF_SAVE_FILENAME:
	case PREF_OPEN_FILENAME:
	case PREF_DIRNAME:
	case PREF_PASSWORD:
		g_free(pref->stashed_val.string);
		pref->stashed_val.string = g_strdup(*pref->varp.string);
		break;

	case PREF_DECODE_AS_RANGE:
	case PREF_RANGE:
		wmem_free(wmem_epan_scope(), pref->stashed_val.range);
		pref->stashed_val.range = range_copy(wmem_epan_scope(), *pref->varp.range);
		break;

	case PREF_COLOR:
		pref->stashed_val.color = *pref->varp.colorp;
		break;

	case PREF_STATIC_TEXT:
	case PREF_UAT:
	case PREF_CUSTOM:
		break;

	case PREF_OBSOLETE:
		ws_assert_not_reached();
		break;
	}
	return 0;
}

guint
pref_unstash(wz_pref_t* pref, gpointer unstash_data_p)
{
	pref_unstash_data_t* unstash_data = (pref_unstash_data_t*)unstash_data_p;
	dissector_table_t sub_dissectors = NULL;
	dissector_handle_t handle = NULL;

	/* Revert the preference to its saved value. */
	switch (pref->type) {

	case PREF_DECODE_AS_UINT:
		if (*pref->varp.uint != pref->stashed_val.uint) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);

			if (unstash_data->handle_decode_as) {
				if (*pref->varp.uint != pref->default_val.uint) {
					dissector_reset_uint(pref->name, *pref->varp.uint);
				}
			}

			*pref->varp.uint = pref->stashed_val.uint;

			if (unstash_data->handle_decode_as) {
				sub_dissectors = find_dissector_table(pref->name);
				if (sub_dissectors != NULL) {
					handle = dissector_table_get_dissector_handle(sub_dissectors, unstash_data->module->title);
					if (handle != NULL) {
						dissector_change_uint(pref->name, *pref->varp.uint, handle);
					}
				}
			}
		}
		break;

	case PREF_UINT:
		if (*pref->varp.uint != pref->stashed_val.uint) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);
			*pref->varp.uint = pref->stashed_val.uint;
		}
		break;

	case PREF_BOOL:
		if (*pref->varp.boolp != pref->stashed_val.boolval) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);
			*pref->varp.boolp = pref->stashed_val.boolval;
		}
		break;

	case PREF_ENUM:
		if (*pref->varp.enump != pref->stashed_val.enumval) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);
			*pref->varp.enump = pref->stashed_val.enumval;
		}
		break;

	case PREF_STRING:
	case PREF_SAVE_FILENAME:
	case PREF_OPEN_FILENAME:
	case PREF_DIRNAME:
	case PREF_PASSWORD:
		if (strcmp(*pref->varp.string, pref->stashed_val.string) != 0) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);
			g_free(*pref->varp.string);
			*pref->varp.string = g_strdup(pref->stashed_val.string);
		}
		break;

	case PREF_DECODE_AS_RANGE:
		if (!ranges_are_equal(*pref->varp.range, pref->stashed_val.range)) {
			guint32 i, j;
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);

			if (unstash_data->handle_decode_as) {
				sub_dissectors = find_dissector_table(pref->name);
				if (sub_dissectors != NULL) {
					handle = dissector_table_get_dissector_handle(sub_dissectors, unstash_data->module->title);
					if (handle != NULL) {
						/* Delete all of the old values from the dissector table */
						for (i = 0; i < (*pref->varp.range)->nranges; i++) {
							for (j = (*pref->varp.range)->ranges[i].low; j < (*pref->varp.range)->ranges[i].high; j++) {
								dissector_delete_uint(pref->name, j, handle);
								decode_build_reset_list(pref->name, dissector_table_get_type(sub_dissectors), GUINT_TO_POINTER(j), NULL, NULL);
							}

							dissector_delete_uint(pref->name, (*pref->varp.range)->ranges[i].high, handle);
							decode_build_reset_list(pref->name, dissector_table_get_type(sub_dissectors), GUINT_TO_POINTER((*pref->varp.range)->ranges[i].high), NULL, NULL);
						}
					}
				}
			}

			wmem_free(wmem_epan_scope(), *pref->varp.range);
			*pref->varp.range = range_copy(wmem_epan_scope(), pref->stashed_val.range);

			if (unstash_data->handle_decode_as) {
				if ((sub_dissectors != NULL) && (handle != NULL)) {

					/* Add new values to the dissector table */
					for (i = 0; i < (*pref->varp.range)->nranges; i++) {

						for (j = (*pref->varp.range)->ranges[i].low; j < (*pref->varp.range)->ranges[i].high; j++) {
							dissector_change_uint(pref->name, j, handle);
							decode_build_reset_list(pref->name, dissector_table_get_type(sub_dissectors), GUINT_TO_POINTER(j), NULL, NULL);
						}

						dissector_change_uint(pref->name, (*pref->varp.range)->ranges[i].high, handle);
						decode_build_reset_list(pref->name, dissector_table_get_type(sub_dissectors), GUINT_TO_POINTER((*pref->varp.range)->ranges[i].high), NULL, NULL);
					}
				}
			}
		}
		break;

	case PREF_RANGE:
		if (!ranges_are_equal(*pref->varp.range, pref->stashed_val.range)) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);
			wmem_free(wmem_epan_scope(), *pref->varp.range);
			*pref->varp.range = range_copy(wmem_epan_scope(), pref->stashed_val.range);
		}
		break;

	case PREF_COLOR:
		if ((pref->varp.colorp->blue != pref->stashed_val.color.blue) ||
			(pref->varp.colorp->red != pref->stashed_val.color.red) ||
			(pref->varp.colorp->green != pref->stashed_val.color.green)) {
			unstash_data->module->prefs_changed_flags |= prefs_get_effect_flags(pref);
			*pref->varp.colorp = pref->stashed_val.color;
		}
		break;

	case PREF_STATIC_TEXT:
	case PREF_UAT:
	case PREF_CUSTOM:
		break;

	case PREF_OBSOLETE:
		ws_assert_not_reached();
		break;
	}
	return 0;
}

static guint Collect_module_prefs(module_t *module, gpointer tree)
{
	GPtrArray* pTree = (GPtrArray*)tree;
	if (!pTree) return 0;

	if (!module->use_gui) {
		/* This module uses its own GUI interface to modify its
		* preferences, so ignore it
		*/
		return 0;
	}

	/*
	* Is this module an interior node, with modules underneath it?
	*/
	if (!prefs_module_has_submodules(module)) {
		/*
		* No.
		* Does it have any preferences (other than possibly obsolete ones)?
		*/
		if (prefs_pref_foreach(module, pref_exists, NULL) == 0) {
			/*
			* No.  Don't put the module into the preferences window,
			* as there's nothing to show.
			*
			* XXX - we should do the same for interior ndes; if the module
			* has no non-obsolete preferences *and* nothing under it has
			* non-obsolete preferences, don't put it into the window.
			*/
			return 0;
		}
	}

	/*
	* Add this module to the tree.
	*/
	wz_Proto_Pref* pwz_Proto_Pref = malloc(sizeof(wz_Proto_Pref));
	g_ptr_array_add(pTree, pwz_Proto_Pref);
	pwz_Proto_Pref->children = NULL;
	pwz_Proto_Pref->name = module->title;
	pwz_Proto_Pref->module = module;

	prefs_pref_foreach(module, pref_stash, NULL);
	/*
	* Is this an interior node?
	*/
	if (prefs_module_has_submodules(module)) {
		/*
		* Yes. Walk the subtree and attach stuff to it.
		*/
		pwz_Proto_Pref->children = g_ptr_array_new();
		prefs_modules_foreach_submodules(module, Collect_module_prefs, (gpointer)pwz_Proto_Pref->children);
	}

	return 0;
}
GPtrArray* wz_Collect_Preferences()
{
	GPtrArray* pTree = g_ptr_array_new();
	prefs_modules_foreach_submodules(NULL, Collect_module_prefs, (gpointer)pTree);
	return pTree;
}
static guint wz_collect_module_pref(wz_pref_t *pref, gpointer user_data)
{
	GPtrArray* pTree = (GPtrArray*)user_data;

	wz_PCappreference* wzPref = malloc(sizeof(wz_PCappreference));
	wzPref->pref = pref;
	wzPref->title = pref->title;
	wzPref->type = pref->type;
	wzPref->tobase = pref->info.base;

	g_ptr_array_add(pTree, wzPref);
	//const char *title;
	//const char *type_name = prefs_pref_type_name(pref);
	//char       *label_string;
	//size_t      label_len;
	//char        uint_str[10 + 1];
	//char *tooltip_txt;

	///* Give this preference a label which is its title, followed by a colon,
	//and left-align it. */
	//title = pref->title;
	//label_len = strlen(title) + 2;
	//label_string = (char *)g_malloc(label_len);
	//g_strlcpy(label_string, title, label_len);

	//tooltip_txt = pref->description ? g_strdup_printf("%s\n\nName: %s.%s\nType: %s",
	//	pref->description,
	//	pwz_module_info->module->name,
	//	pref->name,
	//	type_name ? type_name : "Unknown"
	//) : NULL;

	///*
	//* Sometimes we don't want to append a ':' after a static text string...
	//* If it is needed, we will specify it in the string itself.
	//*/
	//if (pref->type != PREF_STATIC_TEXT)
	//	g_strlcat(label_string, ":", label_len);

	//pref_stash(pref, NULL);

	///* Save the current value of the preference, so that we can revert it if
	//the user does "Apply" and then "Cancel", and create the control for
	//editing the preference. */
	switch (pref->type) {

	case PREF_UINT:
		wzPref->value = pref->stashed_val.uint;
		//	/* XXX - there are no uint spinbuttons, so we can't use a spinbutton.
		//	Even more annoyingly, even if there were, GLib doesn't define
		//	G_MAXUINT - but I think ANSI C may define UINT_MAX, so we could
		//	use that. */
		//	switch (pref->info.base) {

		//	case 10:
		//		g_snprintf(uint_str, sizeof(uint_str), "%u", pref->stashed_val.uint);
		//		break;

		//	case 8:
		//		g_snprintf(uint_str, sizeof(uint_str), "%o", pref->stashed_val.uint);
		//		break;

		//	case 16:
		//		g_snprintf(uint_str, sizeof(uint_str), "%x", pref->stashed_val.uint);
		//		break;
		//	}
		//	pref->control = create_preference_entry(main_grid, pref->ordinal,
		//		label_string, tooltip_txt,
		//		uint_str);
		break;

	case PREF_BOOL:
		wzPref->value = pref->stashed_val.boolval;
		//	pref->control = create_preference_check_button(main_grid, pref->ordinal,
		//		label_string, tooltip_txt,
		//		pref->stashed_val.boolval);
		break;

	case PREF_ENUM:
		wzPref->value = pref->stashed_val.enumval;
		wzPref->radio_buttons = pref->info.enum_info.radio_buttons;
		wzPref->enumvals = pref->info.enum_info.enumvals;
		//if (pref->info.enum_info.radio_buttons) {
			//		/* Show it as radio buttons. */
			//		pref->control = create_preference_radio_buttons(main_grid, pref->ordinal,
			//			label_string, tooltip_txt,
			//			pref->info.enum_info.enumvals,
			//			pref->stashed_val.enumval);
		//}
		//else {
			/* Show it as an option menu. */
	//		pref->control = create_preference_option_menu(main_grid, pref->ordinal,
	//			label_string, tooltip_txt,
	//			pref->info.enum_info.enumvals,
	//			pref->stashed_val.enumval);
		//}
		break;

	case PREF_STRING:
		wzPref->stringValue = pref->stashed_val.string;
		//	pref->control = create_preference_entry(main_grid, pref->ordinal,
		//		label_string, tooltip_txt,
		//		pref->stashed_val.string);
		break;

		//case PREF_FILENAME:
		//	pref->control = create_preference_path_entry(main_grid, pref->ordinal,
		//		label_string,
		//		tooltip_txt,
		//		pref->stashed_val.string, FALSE);
		//	break;

		//case PREF_DIRNAME:
		//	pref->control = create_preference_path_entry(main_grid, pref->ordinal,
		//		label_string,
		//		tooltip_txt,
		//		pref->stashed_val.string, TRUE);
		//	break;

	case PREF_RANGE:
	{
		//	char *range_str_p;

		//	range_str_p = range_convert_range(NULL, *pref->varp.range);
		//	pref->control = create_preference_entry(main_grid, pref->ordinal,
		//		label_string, tooltip_txt,
		//		range_str_p);
		//	wmem_free(NULL, range_str_p);
		break;
	}

	//case PREF_STATIC_TEXT:
	//{
	//	pref->control = create_preference_static_text(main_grid, pref->ordinal,
	//		label_string, tooltip_txt);
	//	break;
	//}

	//case PREF_UAT:
	//{
	//	if (pref->gui == GUI_ALL || pref->gui == GUI_GTK)
	//		pref->control = create_preference_uat(main_grid, pref->ordinal,
	//			label_string, tooltip_txt,
	//			pref->varp.uat);
	//	break;
	//}

	//case PREF_COLOR:
	//case PREF_CUSTOM:
	//	/* currently not supported */

	//case PREF_OBSOLETE:
	//	g_assert_not_reached();
	//	break;
	}
	//g_free(tooltip_txt);
	//g_free(label_string);

	return 0;
}
GPtrArray* wz_Collect_Module_Preferences(module_t* module)
{
	GPtrArray* pTree = g_ptr_array_new();
	prefs_pref_foreach(module, wz_collect_module_pref, (gpointer)pTree);
	return pTree;
}
void wz_update_module_pref(module_t* module, wz_pref_t* pref, guint value, char* stringValue)
{
	switch (pref->type)
	{
	case PREF_UINT: pref->stashed_val.uint = value; break;
	case PREF_BOOL: pref->stashed_val.boolval= value > 0 ? TRUE : FALSE; break;
	case PREF_ENUM: pref->stashed_val.enumval = value; break;
	case PREF_STRING:pref->stashed_val.string = stringValue; break;
	}
}
static guint wz_check_pref(module_t *module, gpointer dummy)
{
	if (!module->use_gui) 
		return 0;

	prefs_pref_foreach(module, pref_unstash, &module->prefs_changed_flags);
	if (prefs_module_has_submodules(module)) 
		prefs_modules_foreach_submodules(module, wz_check_pref, NULL);
}
void wz_apply_all_pref()
{
	prefs_apply_all();

	char *pf_dir_path;
	char *pf_path;
	if (create_persconffile_dir(&pf_dir_path) != -1) 
		write_prefs(&pf_path);

	//prefs_modules_foreach_submodules(NULL, wz_check_pref, NULL);
	//prefs_apply_all();
}
#pragma endregion
#endif