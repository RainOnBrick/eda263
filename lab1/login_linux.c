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

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

int main(int argc, char *argv[]) {

	mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

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

		// Remove trailing newline
		user[strcspn(user, "\n")] = 0;

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

				if (passwddata->pwage > MAX_PW_AGE) {
					printf("You have used your password %d times. Time to change it!\n", passwddata->pwage);
				}

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */
			} else {
				printf("Login Incorrect\n");
				passwddata->pwfailed++;
			}

			mysetpwent(passwddata->pwname, passwddata);
		} else {
			printf("Login Incorrect\n");
		}
	}
	return 0;
}
