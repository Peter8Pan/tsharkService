#pragma once
#ifndef _wz_bridge_h
#define _wz_bridge_h

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <errno.h>

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/ws_getopt.h"
#endif
#include "wsutil/filesystem.h"
#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>
#include <epan/address.h>
#include <epan/secrets.h>

#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>
#include <epan/uat-int.h>
#include <epan/stat_tap_ui.h>
#include "ui/rtp_stream.h"
#include "ui/filter_files.h"
#include <epan/rtp_pt.h>
#include "ui/tap-rtp-common.h"
#include <epan/dissectors/packet-rtp.h>
#include "epan/dissectors/packet-h225.h"

#include "globals.h"
#include <wsutil/wslog.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/util.h"
#include "ui/decode_as_utils.h"
#include "ui/cli/tshark-tap.h"
#include "ui/tap_export_pdu.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/srt_table.h>
#include <epan/rtd_table.h>
#include <epan/ex-opt.h>
#include <epan/exported_pdu.h>
#include <epan/dissectors/packet-sctp.h>
#include <epan/dissectors/packet-wsp.h>
#include <epan/dissectors/packet-rlc-lte.h>
#include <epan/dissectors/packet-mac-lte.h>
#include <epan/follow.h>
#include <epan/prefs-int.h>
#include <epan/expert.h>

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#include <epan/asn1.h>
#include <epan/dissectors/packet-kerberos.h>
#endif

#include "capture_opts.h"
#include "capture/capture_session.h"
#include "ui/capture_info.h"

#ifdef HAVE_LIBPCAP

#ifdef _WIN32

#include <wsutil/os_version_info.h>
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */

#endif /* HAVE_LIBPCAP */

#include <epan/funnel.h>

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#if 0
#define tshark_debug(...) g_warning(__VA_ARGS__)
#else
#define tshark_debug(...)
#endif

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data prev_dis_frame;
static frame_data *prev_cap;
static frame_data prev_cap_frame;

static gboolean perform_two_pass_analysis;

/*
* The way the packet decode is to be written.
*/
typedef enum {
	WRITE_TEXT,   /* summary or detail text */
	WRITE_XML,    /* PDML or PSML */
	WRITE_FIELDS, /* User defined list of fields */
	WRITE_JSON,    /* JSON */
	WRITE_EK      /* JSON bulk insert to Elasticsearch */
	/* Add CSV and the like here */
} output_action_e;

static output_action_e output_action;
static gboolean do_dissection;     /* TRUE if we have to dissect each packet */
static gboolean print_packet_info; /* TRUE if we're to print packet information */
static gint print_summary = -1;    /* TRUE if we're to print packet summary information */
static gboolean print_details;     /* TRUE if we're to print packet details information */
static gboolean print_hex;         /* TRUE if we're to print hex/ascci information */
static gboolean line_buffered;
static gboolean really_quiet = FALSE;

static print_format_e print_format = PR_FMT_TEXT;
static print_stream_t *print_stream;

static gchar **protocolfilter = NULL;

/* The line separator used between packets, changeable via the -S option */
static const char *separator = "";

#ifdef HAVE_LIBPCAP
/*
* TRUE if we're to print packet counts to keep track of captured packets.
*/
static gboolean print_packet_counts;

static capture_options global_capture_opts;
static capture_session global_capture_session;
static info_data_t global_info_data;

#ifdef SIGINFO
static gboolean infodelay;      /* if TRUE, don't print capture info in SIGINFO handler */
static gboolean infoprint;      /* if TRUE, print capture info after clearing infodelay */
#endif /* SIGINFO */

static gboolean capture(void);
static void report_counts(void);
#ifdef _WIN32
static BOOL WINAPI capture_cleanup(DWORD);
#else /* _WIN32 */
static void capture_cleanup(int);
#ifdef SIGINFO
static void report_counts_siginfo(int);
#endif /* SIGINFO */
#endif /* _WIN32 */

#else /* HAVE_LIBPCAP */

static char *output_file_name;

#endif /* HAVE_LIBPCAP */

static void show_capture_file_io_error(const char *, int, gboolean);
static void show_print_file_io_error(int err);
static gboolean write_preamble(capture_file *cf);
static gboolean print_packet(capture_file *cf, epan_dissect_t *edt);
static gboolean write_finale(void);
static const char *cf_open_error_message(int err, gchar *err_info,
	gboolean for_writing, int file_type);

static void open_failure_message(const char *filename, int err,
	gboolean for_writing);
static void failure_message(const char *msg_format, va_list ap);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);
void vsimple_warning_message_box(const char* msg_format, va_list ap){}
void vsimple_error_message_box(const char* msg_format, va_list ap) {}
int real_main(int argc, char* argv[]) { return 1; }

static GHashTable *output_only_tables = NULL;

struct string_elem {
	const char *sstr;   /* The short string */
	const char *lstr;   /* The long string */
};

/** Struct to hold preference data */
typedef struct wz_Preference {
	const char* name;                /**< name of preference */
	const char* title;               /**< title to use in GUI */
	const char* description;         /**< human-readable description of preference */
	int ordinal;                     /**< ordinal number of this preference */
	int type;                        /**< type of that preference */
	unsigned int effect_flags;       /**< Flags of types effected by preference (PREF_TYPE_DISSECTION, PREF_EFFECT_CAPTURE, etc).
										  Flags must be non-zero to ensure saving to disk */
	gui_type_t gui;                  /**< type of the GUI (QT, GTK or both) the preference is registered for */
	union {                          /* The Qt preference code assumes that these will all be pointers (and unique) */
		guint* uint;
		gboolean* boolp;
		gint* enump;
		char** string;
		range_t** range;
		struct epan_uat* uat;
		color_t* colorp;
		GList** list;
	} varp;                          /**< pointer to variable storing the value */
	union {
		guint uint;
		gboolean boolval;
		gint enumval;
		char* string;
		range_t* range;
		color_t color;
		GList* list;
	} stashed_val;                     /**< original value, when editing from the GUI */
	union {
		guint uint;
		gboolean boolval;
		gint enumval;
		char* string;
		range_t* range;
		color_t color;
		GList* list;
	} default_val;                   /**< the default value of the preference */
	union {
		guint base;                    /**< input/output base, for PREF_UINT */
		guint32 max_value;             /**< maximum value of a range */
		struct {
			const enum_val_t* enumvals;  /**< list of name & values */
			gboolean radio_buttons;      /**< TRUE if it should be shown as
											  radio buttons rather than as an
											  option menu or combo box in
											  the preferences tab */
		} enum_info;                   /**< for PREF_ENUM */
	} info;                          /**< display/text file information */
	struct pref_custom_cbs custom_cbs;   /**< for PREF_CUSTOM */
} wz_pref_t;

static gint
string_compare(gconstpointer a, gconstpointer b)
{
	return strcmp(((const struct string_elem *)a)->sstr,
		((const struct string_elem *)b)->sstr);
}

static void
string_elem_print(gpointer data, gpointer not_used _U_)
{
	fprintf(stderr, "    %s - %s\n",
		((struct string_elem *)data)->sstr,
		((struct string_elem *)data)->lstr);
}
static void
tshark_log_handler(const gchar* log_domain, GLogLevelFlags log_level,
	const gchar* message, gpointer user_data)
{
	/* ignore log message, if log_level isn't interesting based
	upon the console log preferences.
	If the preferences haven't been loaded loaded yet, display the
	message anyway.

	The default console_log_level preference value is such that only
	ERROR, CRITICAL and WARNING level messages are processed;
	MESSAGE, INFO and DEBUG level messages are ignored.

	XXX: Aug 07, 2009: Prior tshark g_log code was hardwired to process only
	ERROR and CRITICAL level messages so the current code is a behavioral
	change.  The current behavior is the same as in Wireshark.
	*/
		return;
}

static char *
output_file_description(const char *fname)
{
	char *save_file_string;

	/* Get a string that describes what we're writing to */
	if (strcmp(fname, "-") == 0) {
		/* We're writing to the standard output */
		save_file_string = g_strdup("standard output");
	}
	else {
		/* We're writing to a file with the name in save_file */
		save_file_string = g_strdup_printf("file \"%s\"", fname);
	}
	return save_file_string;
}

static void
print_current_user(void) {
	gchar *cur_user, *cur_group;

	if (started_with_special_privs()) {
		cur_user = get_cur_username();
		cur_group = get_cur_groupname();
		fprintf(stderr, "Running as user \"%s\" and group \"%s\".",
			cur_user, cur_group);
		g_free(cur_user);
		g_free(cur_group);
		if (running_with_special_privs()) {
			fprintf(stderr, " This could be dangerous.");
		}
		fprintf(stderr, "\n");
	}
}

static void
get_tshark_compiled_version_info(GString *str)
{
	/* Capture libraries */
	get_compiled_caplibs_version(str);
}

static void
get_tshark_runtime_version_info(GString *str)
{
#ifdef HAVE_LIBPCAP
	/* Capture libraries */
	g_string_append(str, ", ");
	get_runtime_caplibs_version(str);
#endif

	/* stuff used by libwireshark */
	epan_get_runtime_version_info(str);
}

/*#define USE_BROKEN_G_MAIN_LOOP*/

#ifdef USE_BROKEN_G_MAIN_LOOP
GMainLoop *loop;
#else
gboolean loop_running = FALSE;
#endif
guint32 packet_count = 0;

static const nstime_t *
tshark_get_frame_ts(struct packet_provider_data* prov, guint32 frame_num)
{
	if (prov->ref && prov->ref->num == frame_num)
		return &prov->ref->abs_ts;

	if (prov->prev_dis && prov->prev_dis->num == frame_num)
		return &prov->prev_dis->abs_ts;

	if (prov->prev_cap && prov->prev_cap->num == frame_num)
		return &prov->prev_cap->abs_ts;

	if (prov->frames) {
		frame_data* fd = frame_data_sequence_find(prov->frames, frame_num);

		return (fd) ? &fd->abs_ts : NULL;
	}

	return NULL;
}

static epan_t *
tshark_epan_new(capture_file* cf)
{
	static const struct packet_provider_funcs funcs = {
		tshark_get_frame_ts,
		cap_file_provider_get_interface_name,
		cap_file_provider_get_interface_description,
		NULL,
	};

	return epan_new(&cf->provider, &funcs);
}

#ifdef HAVE_LIBPCAP

/* capture child detected an error */
void
capture_input_error_message(capture_session *cap_session _U_, char *error_msg, char *secondary_error_msg)
{
	cmdarg_err("%s", error_msg);
	cmdarg_err_cont("%s", secondary_error_msg);
}
static void
capture_input_error(capture_session* cap_session _U_, char* error_msg, char* secondary_error_msg)
{
	cmdarg_err("%s", error_msg);
	cmdarg_err_cont("%s", secondary_error_msg);
}

/* capture child detected an capture filter related error */
void
capture_input_cfilter_error_message(capture_session *cap_session, guint i, char *error_message)
{
	capture_options *capture_opts = cap_session->capture_opts;
	dfilter_t         *rfcode = NULL;
	interface_options  interface_opts;

	g_assert(i < capture_opts->ifaces->len);
	interface_opts = g_array_index(capture_opts->ifaces, interface_options, i);

	if (dfilter_compile(interface_opts.cfilter, &rfcode, NULL) && rfcode != NULL) {
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
			interface_opts.cfilter, interface_opts.descr, error_message);
		dfilter_free(rfcode);
	}
	else {
		cmdarg_err(
			"Invalid capture filter \"%s\" for interface '%s'.\n"
			"\n"
			"That string isn't a valid capture filter (%s).\n"
			"See the User's Guide for a description of the capture filter syntax.",
			interface_opts.cfilter, interface_opts.descr, error_message);
	}
}

static gboolean quiet = FALSE;
/* capture child tells us we have a new (or the first) capture file */
gboolean
capture_input_new_file(capture_session *cap_session, gchar *new_file)
{
	capture_options* capture_opts = cap_session->capture_opts;
	capture_file* cf = cap_session->cf;
	gboolean is_tempfile;
	int      err;

	if (really_quiet == FALSE) {
		if (cap_session->state == CAPTURE_PREPARING) {
			ws_message("Capture started.");
		}
		ws_message("File: \"%s\"", new_file);
	}

	ws_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

	/* free the old filename */
	if (capture_opts->save_file != NULL) {

		/* we start a new capture file, close the old one (if we had one before) */
		if (cf->state != FILE_CLOSED) {
			cf_close(cf);
		}

		g_free(capture_opts->save_file);
		is_tempfile = FALSE;

		epan_free(cf->epan);
		cf->epan = tshark_epan_new(cf);
	}
	else {
		/* we didn't had a save_file before, must be a tempfile */
		is_tempfile = TRUE;
	}

	/* save the new filename */
	capture_opts->save_file = g_strdup(new_file);

	/* if we are in real-time mode, open the new file now */
	if (do_dissection) {
		/* this is probably unecessary, but better safe than sorry */
		cap_session->cf->open_type = WTAP_TYPE_AUTO;
		/* Attempt to open the capture file and set up to read from it. */
		switch (cf_open(cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err)) {
		case CF_OK:
			break;
		case CF_ERROR:
			/* Don't unlink (delete) the save file - leave it around,
			   for debugging purposes. */
			g_free(capture_opts->save_file);
			capture_opts->save_file = NULL;
			return FALSE;
		}
	}
	else if (quiet && is_tempfile) {
		cf->state = FILE_READ_ABORTED;
		cf->filename = g_strdup(new_file);
		cf->is_tempfile = is_tempfile;
	}

	cap_session->state = CAPTURE_RUNNING;

	return TRUE;
}



/* capture child tells us we have new packets to read */
void
capture_input_new_packets(capture_session *cap_session, int to_read)
{
//	gboolean      ret;
//	int           err;
//	gchar        *err_info;
//	gint64        data_offset;
//	capture_file *cf = (capture_file *)cap_session->cf;
//	gboolean      filtering_tap_listeners;
//	guint         tap_flags;
//
//#ifdef SIGINFO
//	/*
//	* Prevent a SIGINFO handler from writing to the standard error while
//	* we're doing so or writing to the standard output; instead, have it
//	* just set a flag telling us to print that information when we're done.
//	*/
//	infodelay = TRUE;
//#endif /* SIGINFO */
//
//	/* Do we have any tap listeners with filters? */
//	filtering_tap_listeners = have_filtering_tap_listeners();
//
//	/* Get the union of the flags for all tap listeners. */
//	tap_flags = union_of_tap_listener_flags();
//
//	if (do_dissection) {
//		gboolean create_proto_tree;
//		epan_dissect_t *edt;
//
//		if (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
//			(tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
//			create_proto_tree = TRUE;
//		else
//			create_proto_tree = FALSE;
//
//		/* The protocol tree will be "visible", i.e., printed, only if we're
//		printing packet details, which is true if we're printing stuff
//		("print_packet_info" is true) and we're in verbose mode
//		("packet_details" is true). */
//		edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
//
//		while (to_read-- && cf->wth) {
//			wtap_cleareof(cf->wth);
//			ret = wtap_read(cf->wth, &err, &err_info, &data_offset);
//			if (ret == FALSE) {
//				/* read from file failed, tell the capture child to stop */
//				sync_pipe_stop(cap_session);
//				wtap_close(cf->wth);
//				cf->wth = NULL;
//			}
//			else {
//				ret = wz_process_packet(cf, edt, data_offset, wtap_phdr(cf->wth),
//					wtap_buf_ptr(cf->wth),
//					tap_flags);
//			}
//			if (ret != FALSE) {
//				/* packet successfully read and gone through the "Read Filter" */
//				packet_count++;
//			}
//		}
//
//		epan_dissect_free(edt);
//
//	}
//	else {
//		/*
//		* Dumpcap's doing all the work; we're not doing any dissection.
//		* Count all the packets it wrote.
//		*/
//		packet_count += to_read;
//	}
//
//	if (print_packet_counts) {
//		/* We're printing packet counts. */
//		if (packet_count != 0) {
//			fprintf(stderr, "\r%u ", packet_count);
//			/* stderr could be line buffered */
//			fflush(stderr);
//		}
//	}
//
//#ifdef SIGINFO
//	/*
//	* Allow SIGINFO handlers to write.
//	*/
//	infodelay = FALSE;
//
//	/*
//	* If a SIGINFO handler asked us to write out capture counts, do so.
//	*/
//	if (infoprint)
//		report_counts();
//#endif /* SIGINFO */
}

static void
report_counts(void)
{
	if ((print_packet_counts == FALSE) && (really_quiet == FALSE)) {
		/* Report the count only if we aren't printing a packet count
		as packets arrive. */
		fprintf(stderr, "%u packet%s captured\n", packet_count,
			plurality(packet_count, "", "s"));
	}
#ifdef SIGINFO
	infoprint = FALSE; /* we just reported it */
#endif /* SIGINFO */
}

#ifdef SIGINFO
static void
report_counts_siginfo(int signum _U_)
{
	int sav_errno = errno;
	/* If we've been told to delay printing, just set a flag asking
	that we print counts (if we're supposed to), otherwise print
	the count of packets captured (if we're supposed to). */
	if (infodelay)
		infoprint = TRUE;
	else
		report_counts();
	errno = sav_errno;
}
#endif /* SIGINFO */


/* capture child detected any packet drops? */
void
capture_input_drops(capture_session *cap_session _U_, guint32 dropped)
{
	if (print_packet_counts) {
		/* We're printing packet counts to stderr.
		Send a newline so that we move to the line after the packet count. */
		fprintf(stderr, "\n");
	}

	if (dropped != 0) {
		/* We're printing packet counts to stderr.
		Send a newline so that we move to the line after the packet count. */
		fprintf(stderr, "%u packet%s dropped\n", dropped, plurality(dropped, "", "s"));
	}
}


/*
* Capture child closed its side of the pipe, report any error and
* do the required cleanup.
*/
void
capture_input_closed(capture_session *cap_session, gchar *msg)
{
	if (msg != NULL)
		fprintf(stderr, "tshark: %s\n", msg);

	report_counts();

	loop_running = FALSE;
}

#ifdef _WIN32
static BOOL WINAPI
capture_cleanup(DWORD ctrltype _U_)
{
	/* CTRL_C_EVENT is sort of like SIGINT, CTRL_BREAK_EVENT is unique to
	Windows, CTRL_CLOSE_EVENT is sort of like SIGHUP, CTRL_LOGOFF_EVENT
	is also sort of like SIGHUP, and CTRL_SHUTDOWN_EVENT is sort of
	like SIGTERM at least when the machine's shutting down.

	For now, we handle them all as indications that we should clean up
	and quit, just as we handle SIGINT, SIGHUP, and SIGTERM in that
	way on UNIX.

	We must return TRUE so that no other handler - such as one that would
	terminate the process - gets called.

	XXX - for some reason, typing ^C to TShark, if you run this in
	a Cygwin console window in at least some versions of Cygwin,
	causes TShark to terminate immediately; this routine gets
	called, but the main loop doesn't get a chance to run and
	exit cleanly, at least if this is compiled with Microsoft Visual
	C++ (i.e., it's a property of the Cygwin console window or Bash;
	it happens if TShark is not built with Cygwin - for all I know,
	building it with Cygwin may make the problem go away). */

	/* tell the capture child to stop */
	sync_pipe_stop(&global_capture_session);

	/* don't stop our own loop already here, otherwise status messages and
	* cleanup wouldn't be done properly. The child will indicate the stop of
	* everything by calling capture_input_closed() later */

	return TRUE;
}
#else
static void
capture_cleanup(int signum _U_)
{
	/* tell the capture child to stop */
	sync_pipe_stop(&global_capture_session);

	/* don't stop our own loop already here, otherwise status messages and
	* cleanup wouldn't be done properly. The child will indicate the stop of
	* everything by calling capture_input_closed() later */
}
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

static guint32 selected_frame_number = 0;

static gboolean
process_packet_first_pass(capture_file *cf, epan_dissect_t *edt,
gint64 offset, wtap_rec* rec, Buffer* buf)
{
	frame_data     fdlocal;
	guint32        framenum;
	gboolean       passed;

	/* The frame number of this packet is one more than the count of
	   frames in this packet. */
	framenum = cf->count + 1;

	/* If we're not running a display filter and we're not printing any
	   packet information, we don't need to do a dissection. This means
	   that all packets can be marked as 'passed'. */
	passed = TRUE;

	frame_data_init(&fdlocal, framenum, rec, offset, cum_bytes);

	/* If we're going to run a read filter or a display filter, set up to
	   do a dissection and do so.  (This is the first pass of two passes
	   over the packets, so we will not be printing any information
	   from the dissection or running taps on the packet; if we're doing
	   any of that, we'll do it in the second pass.) */
	if (edt) {
		/* If we're running a read filter, prime the epan_dissect_t with that
		   filter. */
		if (cf->rfcode)
			epan_dissect_prime_with_dfilter(edt, cf->rfcode);

		if (cf->dfcode)
			epan_dissect_prime_with_dfilter(edt, cf->dfcode);

		/* This is the first pass, so prime the epan_dissect_t with the
		   hfids postdissectors want on the first pass. */
		prime_epan_dissect_with_postdissector_wanted_hfids(edt);

		frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
			&cf->provider.ref, cf->provider.prev_dis);
		if (cf->provider.ref == &fdlocal) {
			ref_frame = fdlocal;
			cf->provider.ref = &ref_frame;
		}

		epan_dissect_run(edt, cf->cd_t, rec,
			frame_tvbuff_new_buffer(&cf->provider, &fdlocal, buf),
			&fdlocal, NULL);

		/* Run the read filter if we have one. */
		if (cf->rfcode)
			passed = dfilter_apply_edt(cf->rfcode, edt);
	}

	if (passed) {
		frame_data_set_after_dissect(&fdlocal, &cum_bytes);
		cf->provider.prev_cap = cf->provider.prev_dis = frame_data_sequence_add(cf->provider.frames, &fdlocal);

		/* If we're not doing dissection then there won't be any dependent frames.
		 * More importantly, edt.pi.dependent_frames won't be initialized because
		 * epan hasn't been initialized.
		 * if we *are* doing dissection, then mark the dependent frames, but only
		 * if a display filter was given and it matches this packet.
		 */
		if (edt && cf->dfcode) {
			if (dfilter_apply_edt(cf->dfcode, edt)) {
				g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->provider.frames);
			}

			if (selected_frame_number != 0 && selected_frame_number == cf->count + 1) {
				/* If we are doing dissection and we have a "selected frame"
				 * then load that frame's references (if any) onto the compiled
				 * display filter. Selected frame number is ordinal, count is cardinal. */
				dfilter_load_field_references(cf->dfcode, edt->tree);
			}
		}

		cf->count++;
	}
	else {
		/* if we don't add it to the frame_data_sequence, clean it up right now
		 * to avoid leaks */
		frame_data_destroy(&fdlocal);
	}

	if (edt)
		epan_dissect_reset(edt);

	return passed;
}

static char *
get_line_buf(size_t len)
{
	static char   *line_bufp = NULL;
	static size_t  line_buf_len = 256;
	size_t         new_line_buf_len;

	for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
		new_line_buf_len *= 2)
		;
	if (line_bufp == NULL) {
		line_buf_len = new_line_buf_len;
		line_bufp = (char *)g_malloc(line_buf_len + 1);
	}
	else {
		if (new_line_buf_len > line_buf_len) {
			line_buf_len = new_line_buf_len;
			line_bufp = (char *)g_realloc(line_bufp, line_buf_len + 1);
		}
	}
	return line_bufp;
}

static inline void
put_string(char *dest, const char *str, size_t str_len)
{
	memcpy(dest, str, str_len);
	dest[str_len] = '\0';
}

static inline void
put_spaces_string(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
	size_t i;

	for (i = str_len; i < str_with_spaces; i++)
		*dest++ = ' ';

	put_string(dest, str, str_len);
}

static inline void
put_string_spaces(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
	size_t i;

	memcpy(dest, str, str_len);
	for (i = str_len; i < str_with_spaces; i++)
		dest[i] = ' ';

	dest[str_with_spaces] = '\0';
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
	wtap* wth;
	gchar* err_info;

	wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
	if (wth == NULL)
		goto fail;

	/* The open succeeded.  Fill in the information for this file. */

	cf->provider.wth = wth;
	cf->f_datalen = 0; /* not used, but set it anyway */

	/* Set the file name because we need it to set the follow stream filter.
	   XXX - is that still true?  We need it for other reasons, though,
	   in any case. */
	cf->filename = g_strdup(fname);

	/* Indicate whether it's a permanent or temporary file. */
	cf->is_tempfile = is_tempfile;

	/* No user changes yet. */
	cf->unsaved_changes = FALSE;

	cf->cd_t = wtap_file_type_subtype(cf->provider.wth);
	cf->open_type = type;
	cf->count = 0;
	cf->drops_known = FALSE;
	cf->drops = 0;
	cf->snap = wtap_snapshot_length(cf->provider.wth);
	nstime_set_zero(&cf->elapsed_time);
	cf->provider.ref = NULL;
	cf->provider.prev_dis = NULL;
	cf->provider.prev_cap = NULL;

	cf->state = FILE_READ_IN_PROGRESS;

	/* Create new epan session for dissection. */
	epan_free(cf->epan);
	cf->epan = tshark_epan_new(cf);

	wtap_set_cb_new_ipv4(cf->provider.wth, add_ipv4_name);
	wtap_set_cb_new_ipv6(cf->provider.wth, (wtap_new_ipv6_callback_t)add_ipv6_name);
	wtap_set_cb_new_secrets(cf->provider.wth, secrets_wtap_callback);

	return CF_OK;

fail:
	cfile_open_failure_message(fname, *err, err_info);
	return CF_ERROR;
}

static void
show_capture_file_io_error(const char *fname, int err, gboolean is_close)
{
	char *save_file_string;

	save_file_string = output_file_description(fname);

	switch (err) {

	case ENOSPC:
		cmdarg_err("Not all the packets could be written to the %s because there is "
			"no space left on the file system.",
			save_file_string);
		break;

#ifdef EDQUOT
	case EDQUOT:
		cmdarg_err("Not all the packets could be written to the %s because you are "
			"too close to, or over your disk quota.",
			save_file_string);
		break;
#endif

	case WTAP_ERR_CANT_CLOSE:
		cmdarg_err("The %s couldn't be closed for some unknown reason.",
			save_file_string);
		break;

	case WTAP_ERR_SHORT_WRITE:
		cmdarg_err("Not all the packets could be written to the %s.",
			save_file_string);
		break;

	default:
		if (is_close) {
			cmdarg_err("The %s could not be closed: %s.", save_file_string,
				wtap_strerror(err));
		}
		else {
			cmdarg_err("An error occurred while writing to the %s: %s.",
				save_file_string, wtap_strerror(err));
		}
		break;
	}
	g_free(save_file_string);
}

static void
show_print_file_io_error(int err)
{
	switch (err) {

	case ENOSPC:
		cmdarg_err("Not all the packets could be printed because there is "
			"no space left on the file system.");
		break;

#ifdef EDQUOT
	case EDQUOT:
		cmdarg_err("Not all the packets could be printed because you are "
			"too close to, or over your disk quota.");
		break;
#endif

	default:
		cmdarg_err("An error occurred while printing packets: %s.",
			g_strerror(err));
		break;
	}
}

static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
int file_type)
{
	const char *errmsg;
	static char errmsg_errno[1024 + 1];

	if (err < 0) {
		/* Wiretap error. */
		switch (err) {

		case WTAP_ERR_NOT_REGULAR_FILE:
			errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
			break;

		case WTAP_ERR_RANDOM_OPEN_PIPE:
			/* Seen only when opening a capture file for reading. */
			errmsg = "The file \"%s\" is a pipe or FIFO; TShark can't read pipe or FIFO files in two-pass mode.";
			break;

		case WTAP_ERR_FILE_UNKNOWN_FORMAT:
			/* Seen only when opening a capture file for reading. */
			errmsg = "The file \"%s\" isn't a capture file in a format TShark understands.";
			break;

		case WTAP_ERR_UNSUPPORTED:
			/* Seen only when opening a capture file for reading. */
			g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"The file \"%%s\" contains record data that TShark doesn't support.\n"
				"(%s)",
				err_info != NULL ? err_info : "no information supplied");
			g_free(err_info);
			errmsg = errmsg_errno;
			break;

		case WTAP_ERR_CANT_WRITE_TO_PIPE:
			/* Seen only when opening a capture file for writing. */
			g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
				"written to a pipe.", wtap_file_type_subtype_short_string(file_type));
			errmsg = errmsg_errno;
			break;

		case WTAP_ERR_UNWRITABLE_FILE_TYPE:
			/* Seen only when opening a capture file for writing. */
			errmsg = "TShark doesn't support writing capture files in that format.";
			break;

		case WTAP_ERR_UNWRITABLE_ENCAP:
			/* Seen only when opening a capture file for writing. */
			g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"TShark can't save this capture as a \"%s\" file.",
				wtap_file_type_subtype_short_string(file_type));
			errmsg = errmsg_errno;
			break;

		case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
			if (for_writing) {
				g_snprintf(errmsg_errno, sizeof(errmsg_errno),
					"TShark can't save this capture as a \"%s\" file.",
					wtap_file_type_subtype_short_string(file_type));
				errmsg = errmsg_errno;
			}
			else
				errmsg = "The file \"%s\" is a capture for a network type that TShark doesn't support.";
			break;

		case WTAP_ERR_BAD_FILE:
			/* Seen only when opening a capture file for reading. */
			g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"The file \"%%s\" appears to be damaged or corrupt.\n"
				"(%s)",
				err_info != NULL ? err_info : "no information supplied");
			g_free(err_info);
			errmsg = errmsg_errno;
			break;

		case WTAP_ERR_CANT_OPEN:
			if (for_writing)
				errmsg = "The file \"%s\" could not be created for some unknown reason.";
			else
				errmsg = "The file \"%s\" could not be opened for some unknown reason.";
			break;

		case WTAP_ERR_SHORT_READ:
			errmsg = "The file \"%s\" appears to have been cut short"
				" in the middle of a packet or other data.";
			break;

		case WTAP_ERR_SHORT_WRITE:
			errmsg = "A full header couldn't be written to the file \"%s\".";
			break;

		case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
			errmsg = "This file type cannot be written as a compressed file.";
			break;

		case WTAP_ERR_DECOMPRESS:
			/* Seen only when opening a capture file for reading. */
			g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"The compressed file \"%%s\" appears to be damaged or corrupt.\n"
				"(%s)",
				err_info != NULL ? err_info : "no information supplied");
			g_free(err_info);
			errmsg = errmsg_errno;
			break;

		default:
			g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"The file \"%%s\" could not be %s: %s.",
				for_writing ? "created" : "opened",
				wtap_strerror(err));
			errmsg = errmsg_errno;
			break;
		}
	}
	else
		errmsg = file_open_error_message(err, for_writing);
	return errmsg;
}

/*
* Open/create errors are reported with an console message in TShark.
*/
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
	fprintf(stderr, "tshark: ");
	fprintf(stderr, file_open_error_message(err, for_writing), filename);
	fprintf(stderr, "\n");
}

/*
* General errors are reported with an console message in TShark.
*/
static void
failure_message(const char *msg_format, va_list ap)
{
	fprintf(stderr, "tshark: ");
	vfprintf(stderr, msg_format, ap);
	fprintf(stderr, "\n");
}

/*
* Read errors are reported with an console message in TShark.
*/
static void
read_failure_message(const char *filename, int err)
{
	cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
		filename, g_strerror(err));
}

/*
* Write errors are reported with an console message in TShark.
*/
static void
write_failure_message(const char *filename, int err)
{
	cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
		filename, g_strerror(err));
}

/*
* Report additional information for an error in command-line arguments.
*/
static void
failure_message_cont(const char *msg_format, va_list ap)
{
	vfprintf(stderr, msg_format, ap);
	fprintf(stderr, "\n");
}

/*
* Editor modelines  -  https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 2
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* vi: set shiftwidth=2 tabstop=8 expandtab:
* :indentSize=2:tabSize=8:noTabs=true:
*/

//BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
//{
//	return TRUE;
//}

//peter added the followings
#include <stdbool.h>

#define COLUMN_FIELD_FILTER  "_ws.col."

typedef struct _wz_output_fields {
	gboolean		print_bom;
	gboolean		print_header;
	gchar			separator;
	gchar			occurrence;
	gchar			aggregator;
	GPtrArray*		fields;
	GHashTable*		field_indicies;
	gpointer*		field_values;
	gchar			quote;
	gboolean		includes_col_fields;
} wz_output_fields;
typedef struct _wz_simple_treenode
{
	char* name;
	void* abbrev;
	GPtrArray* children;
} wz_simple_treenode;
typedef struct _wz_simple_table
{
	char* name;
	char* filter;
	GPtrArray* columns;
	GPtrArray* subTables;
} wz_simple_table;
typedef struct _wz_simple_subtable
{
	char* name;
	GPtrArray* Rows;
} wz_simple_subtable;
typedef struct _wz_simple_field
{
	double float_value;
	const char* string_value;
} wz_simple_field;
typedef struct _wz_srt_table
{
	char* type;
	char* filter;
	GPtrArray* Rows;
} wz_srt_table;
typedef struct _wz_srt_row
{
	char* procedure;
	guint samples;
	gint minSec;
	gint minnSec;
	gint maxSec;
	gint maxnSec;
	gint avgSec; 
	gint avgnSec;
	gint sumSec;
	gint sumnSec;
} wz_srt_row;
typedef struct _wz_sip_stats {
	char	    *filter;
	guint32	     packets;	 /* number of sip packets, including continuations */
	guint32	     resent_packets;
	guint32	     average_setup_time;
	guint32	     max_setup_time;
	guint32	     min_setup_time;
	GPtrArray*			RequestArray;//wz_sip_stats_item array
	GPtrArray*			ResponseArray;//wz_sip_stats_item array
} wz_sip_stats;

typedef struct _wz_sip_stats_item {
	const char * name;
	guint32		 code;
	guint32	     packets;	 /* number of sip packets, including continuations */
	guint32	     resent_packets;
	guint32	     average_setup_time;
	guint32	     max_setup_time;
	guint32	     min_setup_time;
} wz_sip_stats_item;

typedef struct _wz_sctp{
	guint32 totalPackeks;
	GPtrArray* Items;
} wz_sctp;
typedef struct _wz_sctp_item {
	char * srcAddr;
	char * destAddr;
	guint16 sport;
	guint16 dport;
	guint32 Data;
	guint32 Sack;
	guint32 HBeat;
	guint32 HBeatAck;
	guint32 Init;
	guint32 InitAck;
	guint32 Cookie;
	guint32 CookieAck;
	guint32 Abort;
	guint32 Error;
} wz_sctp_item;
typedef struct _wz_wsp {
	GPtrArray* WSP;
	GPtrArray* ReplyPackets;
} wz_wsp;
typedef struct _wz_wsp_item {
	const char * pduType;
	guint32 packets;
}wz_wsp_item;
typedef struct _wz_wsp_reply_item {
	gint StatusCode;
	guint32 packets;
	char* Name;
} wz_wsp_reply_item;
typedef struct wz_rlc_lte {
	guint16 number_of_ues;
	guint32 total_frames;

	guint32 bcch_frames;
	guint32 bcch_bytes;
	guint32 pcch_frames;
	guint32 pcch_bytes;

	GPtrArray* Rows;
} wz_rlc_lte;
typedef struct wz_rlc_lte_row_data {
	/* Key for matching this row */
	guint16  ueid;

	gboolean is_predefined_data;

	guint32  UL_frames;
	guint32  UL_total_bytes;
	nstime_t UL_time_start;
	nstime_t UL_time_stop;
	guint32  UL_total_acks;
	guint32  UL_total_nacks;
	guint32  UL_total_missing;

	guint32  DL_frames;
	guint32  DL_total_bytes;
	nstime_t DL_time_start;
	nstime_t DL_time_stop;
	guint32  DL_total_acks;
	guint32  DL_total_nacks;
	guint32  DL_total_missing;

	gfloat UL_bw;
	gfloat DL_bw;
} wz_rlc_lte_row_data;
typedef struct wz_mac_lte {
	guint16 max_ul_ues_in_tti;
	guint32 max_dl_ues_in_tti;

	guint32 mib_frames;
	guint32 sib_frames;
	guint32 sib_bytes;
	guint32 pch_frames;
	guint32 pch_bytes;
	guint32 pch_paging_ids;
	guint32 rar_frames;
	guint32 rar_entries;
	guint16 number_of_ues;
	guint16 number_of_rntis;
	guint16 number_of_ueids;

	GPtrArray* Rows;
} wz_mac_lte;
typedef struct wz_mac_lte_row_data {
	guint16  rnti;
	guint8   rnti_type;
	guint16  ueid;

	gboolean is_predefined_data;

	guint32  UL_frames;
	guint32  UL_raw_bytes;   /* all bytes */
	guint32  UL_total_bytes; /* payload */
	nstime_t UL_time_start;
	nstime_t UL_time_stop;
	guint32  UL_padding_bytes;
	guint32  UL_CRC_errors;
	guint32  UL_retx_frames;

	guint32  DL_frames;
	guint32  DL_raw_bytes;   /* all bytes */
	guint32  DL_total_bytes;
	nstime_t DL_time_start;
	nstime_t DL_time_stop;
	guint32  DL_padding_bytes;

	guint32  DL_CRC_failures;
	guint32  DL_CRC_high_code_rate;
	guint32  DL_CRC_PDSCH_lost;
	guint32  DL_CRC_Duplicate_NonZero_RV;
	guint32  DL_retx_frames;

	gfloat DL_Pad;
	gfloat UL_Pad;
	gfloat UL_bw;
	gfloat DL_bw;
} wz_mac_lte_row_data;

typedef struct _wz_io_stat_t {
	guint64 interval;     /* The user-specified time interval (us) */
	guint64 duration;     /* The user-specified time interval (us) */
	guint invl_prec;	 /* Decimal precision of the time interval (1=10s, 2=100s etc) */
	int num_cols;         /* The number of columns of stats in the table */
	struct _io_stat_item_t *items;  /* Each item is a single cell in the table */
	time_t start_time;    /* Time of first frame matching the filter */
	const char **filters; /* 'io,stat' cmd strings (e.g., "AVG(smb.time)smb.time") */
} wz_io_stat_t;

typedef struct _wz_rtp_stat {
	char * src_addr;
	guint32 src_port;
	char * dst_addr;
	guint32 dest_port;
	guint32 ssrc;
	char * payload_type;
	guint32 packet_count;
	gint32 lost;
	double perc;
	double max_delta;
	double max_jitter;
	double mean_jitter;
	gboolean problem;
	GPtrArray* packets;
} wz_rtp_stat;

typedef struct _wz_rtp_Packet {
	gint64 time;       /**< Unit is ms */
	guint32 PacketIndex;
	guint32 sequence;
	double delta;
	double jitter;
	double skew;
	double bandwidth;
	gboolean problem;
	
	guint32 delta_timestamp;
	guint8 info_padding_count;
} wz_rtp_Packet;

typedef struct _wz_voip_calls_info {
	const gchar*         call_state;
	gchar*                  call_id;
	gchar*                  from_identity;
	gchar*                  to_identity;
	gchar*                 initial_speaker;
	guint32                 npackets;
	gchar*                  protocol_name;
	gchar*					call_comment;
	guint16                 call_num;

	/**> The frame_data struct holds the frame number and timing information needed. */
	frame_data             *start_fd;
	double                start_rel_ts;
	frame_data             *stop_fd;
	double                stop_rel_ts;
} wz_voip_calls_info_t;
typedef struct _wz_seq_analysis_item {
	guint32 frame_number;
	gchar* src_addr;
	guint16 port_src;
	gchar* dst_addr;
	guint16 port_dst;
	gchar *frame_label;                 /**< the label on top of the arrow */
	gchar *time_str;                    /**< timestamp */
	gchar *comment;                     /**< a comment that appears at the right of the graph */
	guint16 conv_num;                   /**< The conversation number. Used for coloring VoIP calls. */
	gchar *protocol;                    /**< the label of the protocol defined in the IP packet */
} wz_seq_analysis_item_t;

typedef struct _wz_Proto_Pref {
	gchar* name;
	module_t* module;
	GPtrArray* children;
} wz_Proto_Pref;
typedef struct _wz_PCappreference {
	pref_t *pref;
	const char* title;//const char*   /**< title to use in GUI */
	gint type;                        /**< type of that preference */
	guint value;
	gint tobase;
	char* stringValue;
	const enum_val_t *enumvals;
	gboolean radio_buttons;
} wz_PCappreference;

typedef struct
{
	//fileds and their corresponding data
	guint8				FrameIndexInsteadOfTime;
	int					FieldCount;
	ftenum_t*			output_field_ftype;
	GArray**			FieldDataArrays;
	GArray**			FieldIndexArrays;
	guint8*				FieldNeedIndexArray;
	guint8*				FieldNeedSaved;
	//frame info
	GArray**			FrameInfo;
	GPtrArray*			errorInfo;
	//frame summary
	GPtrArray*			FrameSummary;

	wz_simple_treenode*	pSimple_tree_node;
} wz_LoadResult;

guint8  UI8_MAX = _UI8_MAX;
guint16  UI16_MAX = _UI16_MAX;
guint32  UI32_MAX = _UI32_MAX;
guint64  UI64_MAX = _UI64_MAX;
gint8  I8_MAX = _I8_MAX;
gint16  I16_MAX = _I16_MAX;
gint32  I32_MAX = _I32_MAX;
gint64  I64_MAX = _I64_MAX;
gfloat F_MAX = G_MAXFLOAT;
gdouble D_MAX = G_MAXDOUBLE;

typedef struct
{
	capture_file		cfile;

	int					linktype;
	guint32				frameIndex;
	gint64				data_offset;
	gboolean			filtering_tap_listeners;
	guint				tap_flags;
	epan_dissect_t*		edt;
	e_prefs*            prefs_p;

	wz_output_fields	output_fields;
	BYTE*				output_fieldLoadFlags;

	wz_LoadResult*			pLoadResult;
} wz_LoadFileStatus;

typedef struct
{
	char* cf_name;
	char* filter;
	int outputFlag;
	int ShallCreateProtocolTree;

	guint8 FrameIndexInsteadOfTime;
	int fieldCount;
	char** requestedFields;
	BYTE* requestedFieldLoadFlags;

	int cmdCount;
	char** requestedCmds;
	//guint32 frameNumber;
	gint64 filePosition;

} wz_LoadParameters;

static void wz_proto_tree_get_node_field_values(wz_LoadFileStatus *pLoadFileStatus, proto_node *node);
static void wz_proto_tree_children_foreach(wz_LoadFileStatus *pLoadFileStatus, proto_tree *tree);
static int proto_data = -1;

/*
exported functions 
*/
__declspec(dllexport) extern int wz_Initialize(char* szDllDir);
__declspec(dllexport) extern void wz_Free_EntireWiresharkResource(void);

__declspec(dllexport) extern char ** wz_GetProtocolFieldNames(int* arrayLength);
__declspec(dllexport) extern void wz_Free_GetProtocolFieldNames(char ** pointer);
__declspec(dllexport) extern int wz_IsLayer3(char* szShortName);

__declspec(dllexport) extern wz_LoadResult* wz_LoadPcapFile(wz_LoadParameters* loadParameters);

__declspec(dllexport) extern void wz_Free_LoadResultOfField(wz_LoadResult* pLoadResult, int fieldIndex);
__declspec(dllexport) extern void wz_Free_LoadResult(wz_LoadResult* pLoadResult);
__declspec(dllexport) extern void wz_G_Free(void* pData);
__declspec(dllexport) extern void wz_g_byte_array_free(void* pData);
__declspec(dllexport) extern void wz_g_ptr_array_free(void* pData);

__declspec(dllexport) extern char* wz_address_to_str(address *addr, int resolveName);
__declspec(dllexport) extern GPtrArray* wz_Collect_Preferences();
__declspec(dllexport) extern GPtrArray* wz_Collect_Module_Preferences(module_t* module);
__declspec(dllexport) extern void wz_update_module_pref(module_t* module, pref_t* pref, guint value, char* stringValue);
__declspec(dllexport) extern void wz_apply_all_pref();
#endif