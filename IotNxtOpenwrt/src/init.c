/*
 * init.c
 *
 *  Created on: 04 Feb 2019
 *      Author: hein
 */


#include <fcntl.h>  /* fcntl, open */
#include <unistd.h>
#include <sys/stat.h>


#include "config.h"
#include "timer.h"
#include "ssl.h"
#include "io.h"


#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netdb.h>


#include <jansson.h>


#include <openssl/opensslv.h>


#include "init.h"
#include "utils.h"
#include "defines.h"


const char *directories [ ] = {  Log_dir,
                                 NULL         };



void setup_signals(char *argv[]);




char hostname [128] = {0};



void create_dir (const char *dir)
{
  struct stat st;

  if ( stat ( dir, &st ) != 0 ) // not present
  {
    DEBUG_PRINTF( "mkdir(%s,0777)", dir );
    mkdir ( dir, 0777 );
  }
}



void init_dir ( void )
{
  int i = 0;

  while ( directories [ i ] )
  {
    create_dir (directories [i]);
    i ++;
  }
}



void daemonize ( void )
{
  pid_t pid, sid;

  // already a daemon
  if (getppid() == 1)
  return;

  // Fork off the parent process
  pid = fork();
  if (pid < 0)
  {
    exit(EXIT_FAILURE);
  }
  // If we got a good PID, then we can exit the parent process.
  if (pid > 0)
  {
    exit(EXIT_SUCCESS);
  }

  // At this point we are executing as the child process

  // Change the file mode mask
  umask(0);

  // Create a new SID for the child process
  sid = setsid();

  if (sid < 0)
  {
    exit(EXIT_FAILURE);
  }

  // Change the current working directory.  This prevents the current directory from being locked; hence not being able to remove it.
//   if ((chdir("/")) < 0)
//   {
//      exit(EXIT_FAILURE);
//   }

  // Redirect standard files to /dev/null
  freopen("/dev/null", "r", stdin);
  freopen("/dev/null", "w", stdout);
  freopen("/dev/null", "w", stderr);

  redirect_stdio();
}





void correct_path ( char *argv [ ] )
{
  if (getppid() == 1)  // daemon
  {
    //  char cwd[100];
    char *path, *p;

    //  DEBUG_PRINTF("argv[0] is '%s'", argv[0]);

    path = strdup ( argv [ 0 ] );

    p = path + strlen ( path ) - 1;

    while ( *p )
    {
      if ( *p == '/' )
      {
        *p = '\0';

  //      DEBUG_PRINTF("path is '%s'", path);

        chdir ( path );
  //      getcwd(cwd,sizeof(cwd));

  //      DEBUG_PRINTF("cwd is '%s'", cwd);

        break;// from while
      }

      p --;
    }

    free ( path );
  }
}





void one_msec_poll ( void *userdata )
{
  io_poll (__func__);
}



int IsDebuggerPresent(void)
{
  char buf[1024];
  int debugger_present = 0;

  int status_fd = open("/proc/self/status", O_RDONLY);
  if (status_fd == -1)
    return 0;

  ssize_t num_read = read(status_fd, buf, sizeof(buf) - 1);

  if (num_read > 0)
  {
    static const char TracerPid[] = "TracerPid:";
    char *tracer_pid;

    buf[num_read] = 0;
    tracer_pid = strstr(buf, TracerPid);
    if (tracer_pid)
      debugger_present = !!atoi(tracer_pid + sizeof(TracerPid) - 1);
  }

  return debugger_present;
}



void init (int argc, char *argv [])
{
  if ( gethostname ( hostname, sizeof ( hostname ) ) != 0 )    strcpy ( hostname, "unknown" );
#if defined(__x86_64__)
  printf("compiled X64 (%s)\n", hostname );
#elif defined(__i386__)
  printf("compiled i386 (%s)\n", hostname);
#elif defined(__arm__)
  printf("compiled armv6l (%s)\n", hostname);
#else
#error "No definition for CPU\n"
#endif

  if ( JANSSON_VERSION_HEX < 0x020800)
  {
    printf ("Lib Jansson version too low %d.%d < 2.8\n", JANSSON_MAJOR_VERSION, JANSSON_MINOR_VERSION);
    abort();
  }

//  if ( OPENSSL_VERSION_NUMBER < 0x100020efL)
//  {
//    DEBUG_PRINTF("Lib openssl version too low (%s) < (OpenSSL 1.0.2n  7 Dec 2017)", OPENSSL_VERSION_TEXT);
//    abort();
//  }

  correct_path (argv);

  if (!IsDebuggerPresent ())
  {
    printf ("daemonising!\n");
    daemonize ();
  }

  setup_signals (argv);

  init_dir ();

  Timer_Init ();

//  LoadConfigurationData (argc, argv, "Config.xml");

  if (!config.api_host)
    config.api_host = strdup ("https://prototype.iotnxt.io/api/v3/data/post");
  if (!config.api_user)
    config.api_user = strdup ("api");
  if (!config.api_pass)
    config.api_pass  = strdup ("dgcszsu7qhb5f3p0prcf1ckqpwimeydi");


  // write luci files
  // open /usr/lib/lua/luci/controller/admin/index.lua
  // look for line -- Logout is last
  // add before logout:
  //  page = node("admin", "iot")
  //  page.title = _("IoT")
  //  page.order = 60
  //  page.index = true
  //  toplevel_page(page, "admin/iot/overview", alias("admin", "iot", "overview"))
  // write a file /usr/lib/lua/luci/controller/admin/iot.lua
  //  module("luci.controller.admin.iot", package.seeall)
  //
  //  function index()
  //    entry({"admin", "iot", "overview"}, template("admin_iot/index"), _("Overview"), 1)
  //
  //  end
  // mkdir /usr/lib/lua/luci/view/admin_iot
  // write a file /usr/lib/lua/luci/view/admin_iot/index.htm


  init_sockets ();

  init_openssl (hostname, argv[0], (int)GetUcTimeStamp());

  Timer_Add (1, MultiShot, one_msec_poll, NULL);
}

