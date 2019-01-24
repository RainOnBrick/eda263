/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define MAX_PW_AGE 10
#define MAX_FAILED_ATTEMPTS 5

typedef void (*sighandler_t)(int);

void safe_sighandler(int signum, sighandler_t handler) {
	if (signal(signum, handler) == SIG_ERR) {
		printf("Unable to override signal handler for %d\n", signum);
		exit(0);
	}
}

void sighandler() {
	safe_sighandler(SIGINT, SIG_IGN);
	safe_sighandler(SIGQUIT, SIG_IGN);
	safe_sighandler(SIGABRT, SIG_IGN);
	safe_sighandler(SIGTERM, SIG_IGN);
	safe_sighandler(SIGTSTP, SIG_IGN);
}

int main(int argc, char *argv[]) {
	mypwent *passwddata;

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char *c_pass;
	char prompt[] = "password: ";
	char *user_pass;

	char *shell_argv[] = {"/bin/sh", 0};
	char *shell_envp[] = {0};

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL)
			exit(0);

		user[strcspn(user, "\n")] = 0; /* Remove trailing newline */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			if (passwddata->pwfailed > MAX_FAILED_ATTEMPTS) {
				printf("You're account has been locked due to too many failed login attempts. Please contact a system administrator to unlock your account.\n");
				exit(0);
			}

			c_pass = crypt(user_pass, passwddata->passwd_salt);

			if (!strcmp(c_pass, passwddata->passwd)) {
				printf("You're in! Previously failed attempts: %d\n", passwddata->pwfailed);

				passwddata->pwfailed = 0;
				passwddata->pwage++;
				if (mysetpwent(passwddata->pwname, passwddata)) {
					printf("Failed to write user info to passdb. Exiting...\n");
					exit(0);
				}

				if (passwddata->pwage > MAX_PW_AGE) {
					printf("You have used your password %d times. Time to change it!\n", passwddata->pwage);
				}

				if (setuid(passwddata->uid)) {
					printf("Failed to set uid for shell. Exiting...\n");
					exit(0);
				}
				if (execve(shell_argv[0], &shell_argv[0], shell_envp)) {
					printf("Failed to open shell for user. Exiting...\n");
					exit(0);
				}
			} else {
				printf("Login incorrect\n");
				passwddata->pwfailed++;
				if (mysetpwent(passwddata->pwname, passwddata)) {
					printf("Failed to write user info to passdb. Exiting...\n");
					exit(0);
				}
			}
		} else {
			printf("Login incorrect\n");
		}
	}
	return 0;
}
