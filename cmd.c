// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define PIPE_READ	0
#define PIPE_WRITE	1
char old_pwd[4048];
int old_pwd_set;
/**
 * Parse through words and concatenate the values of environment variables
 * or just the values of the words
 */
char *verify_variables(word_t *word)
{
	// Allocate initial memory for an empty string
	char *value = malloc(1);

	value[0] = '\0';
	// Iterate through the words and concatenate the values
	word_t *curr = word;

	while (curr != NULL) {
		// If the word is an environment variable,
		// get value if existent and concatenate it
		if (curr->expand == 1) {
			char *value_curr = getenv(curr->string);

			// If the variable does not exist, set it to an empty string
			if (value_curr == NULL)
				value_curr = "";

		// Concatenate the value to the string
			value = realloc(value, strlen(value) + strlen(value_curr) + 1);
			strcat(value, value_curr);
		} else {
			value = realloc(value, strlen(value) + strlen(curr->string) + 1);
			strcat(value, curr->string);
		}
		// Go to the next word
		curr = curr->next_part;
	}

	return value;
}
/**
 * Redirect the input/output/error to the files specified in the command
 */
void set_files(simple_command_t *s)
{
	if (s->in != NULL) {
		char *path = verify_variables(s->in);
		int fd = open(path, O_RDONLY);

		if (fd == -1) {
			perror("open");
			exit(1);
			}
			dup2(fd, STDIN_FILENO);
			close(fd);
	}

	if ((s->out != NULL && s->err == NULL) ||
	(s->out != NULL && s->err != NULL && strcmp(s->out->string, s->err->string))) {
		if (s->io_flags == IO_OUT_APPEND) {
			char *path = verify_variables(s->out);
			int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);

			if (fd == -1) {
				perror("open");
				exit(1);
			}
			dup2(fd, STDOUT_FILENO);
			close(fd);
			free(path);
		} else {
			char *path = verify_variables(s->out);
			int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

			if (fd == -1) {
				perror("open");
				exit(1);
			}
			dup2(fd, STDOUT_FILENO);
			close(fd);
			free(path);
		}
	}
	if ((s->err && s->out == NULL) ||
	(s->err != NULL && s->out != NULL && strcmp(s->out->string, s->err->string))) {
		if (s->io_flags == IO_ERR_APPEND) {
			char *path = verify_variables(s->err);
			int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);

			if (fd == -1) {
				perror("open");
				exit(1);
			}
			dup2(fd, STDERR_FILENO);
			close(fd);
			free(path);
		} else {
			char *path = verify_variables(s->err);
			int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

			if (fd == -1) {
				perror("open");
				exit(1);
			}
			dup2(fd, STDERR_FILENO);
			close(fd);
			free(path);
		}
	}

	if (s->out && s->err && !strcmp(s->out->string, s->err->string)) {
		char *path = verify_variables(s->err);
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

		if (fd == -1) {
			perror("open");
			exit(1);
		}
		dup2(fd, STDERR_FILENO);
		dup2(fd, STDOUT_FILENO);
		close(fd);
		free(path);
	}

}

static bool shell_pwd(simple_command_t *s)
{
	pid_t pid = fork();

	if (pid == 0) {
		// child process
		// Redirect
		set_files(s);
		// Execute the command
		char *args[] = {((char *)(s->verb->string)), NULL};

		if (execvp(args[0], args) == -1) {
			fprintf(stderr, "Execution failed for '%s'\n", args[0]);
			exit(1);
		}
		exit(0);
	} else {
		// parent process
		int status;

		if (waitpid(pid, &status, 0) > 0) {
			if (WIFEXITED(status) && !WEXITSTATUS(status))
				return EXIT_SUCCESS;

		return EXIT_FAILURE;
		}
	}

	return EXIT_FAILURE;
}
/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (dir == NULL)
		return EXIT_FAILURE;

	if (strcmp(dir->string, "..") == 0) {
		char curr_pwd[4048];

		// Get the current working directory
		if (getcwd(curr_pwd, sizeof(curr_pwd)) == NULL) {
			perror("getcwd");
			return 1;
		}

		// Get the last slash in the string
		char *last_slash = strrchr(curr_pwd, '/');

		if (last_slash != NULL) {
			// Set the slash to '\0' to truncate the string
			*last_slash = '\0';
		}

		// Save current directory in old_pwd
		if (getcwd(old_pwd, sizeof(old_pwd)) == NULL) {
			perror("getcwd");
			return 1;
		}

		// Set the old_pwd_set flag
		old_pwd_set = 1;
		// Change directory
		return chdir(curr_pwd);
	} else if (strcmp(dir->string, "-") == 0) {
		// Check if old_pwd is set
		if (old_pwd_set == 0) {
			printf("cd: OLDPWD not set\n");
			return 1;
		}

		char pwd[4048];

		strcpy(pwd, old_pwd);
		// Save current directory in old_pwd
		if (getcwd(old_pwd, sizeof(old_pwd)) == NULL) {
			perror("getcwd");
			return 1;
		}
		// Change directory to old_pwd which is now in pwd
		return chdir(pwd);
	}

	// Save current directory in old_pwd
	if (getcwd(old_pwd, sizeof(old_pwd)) == NULL) {
		perror("getcwd");
		return EXIT_FAILURE;
	}

	// Set the old_pwd_set flag
	old_pwd_set = 1;
	// Change directory
	return chdir(dir->string);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Execute exit/quit. */
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */
	if (s == NULL)
		return EXIT_FAILURE;

	/* If builtin command, execute the command. */
	if (strcmp(s->verb->string, "exit") == 0) {
		return shell_exit();
	} else if (strcmp(s->verb->string, "quit") == 0) {
		return shell_exit();
	} else if (strcmp(s->verb->string, "cd") == 0) {
		// Check if there are any file arguments
		// If there are, create them if they don't exist
		if (s->out != NULL || s->err != NULL) {
			int fd = open(s->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0666);

			if (fd == -1) {
				perror("open");
				exit(1);
			}
			close(fd);
		}
		// Call shell_cd
		return shell_cd(s->params);
	} else if (strcmp(s->verb->string, "pwd") == 0) {
		// Call shell_pwd
		return shell_pwd(s);
	}

	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL && s->verb->next_part->string[0] == '=') {
		char *var = ((char *)(s->verb->string));
		// Extract value
		char *value = verify_variables(s->verb->next_part->next_part);

		// Set the environment variable
		if (setenv(var, value, 1) == -1) {
			perror("setenv");
			free(value);
			return 1;
		}
		free(value);
		return EXIT_SUCCESS;
	}

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid = fork();

	if (pid == 0) {
		// Child process
		// Perform redirections
		set_files(s);
		// Load command
		char *args[] = {((char *)(s->verb->string))};

		// If command is a variable
		if (s->verb->expand == 1) {
			// Get the value of the variable
			char *var = ((char *)(s->verb->string));
			char *value = getenv(var);

			// If the variable is not set, get the empty string
			if (value == NULL)
				value = "";
			// Set the first argument to the value of the variable
			args[0] = value;
		}
		int i = 1;

		// Add the rest of the arguments
		for (word_t *word = s->params; word != NULL; word = word->next_word) {
			for (word_t *curr = word; curr != NULL; curr = curr->next_part) {
				if (curr->expand == 1) {
					char *var = ((char *)(curr->string));
					char *value = getenv(var);

					if (value == NULL) {
						value = "";
					} else {
						args[i] = value;
						i++;
					}
				} else {
					args[i] = ((char *)(curr->string));
					i++;
				}
			}
		}
		args[i] = NULL;
		// Execute command
		if (execvp(args[0], args) == -1) {
			// If execvp fails, print error message and exit
			fprintf(stderr, "Execution failed for '%s'\n", args[0]);
			exit(1);
		}
		exit(0);
	} else if (pid > 0) {
		// Parent process
		int status;
		// Wait for child
		if (waitpid(pid, &status, 0) > 0) {
			if (WIFEXITED(status) && !WEXITSTATUS(status))
				return EXIT_SUCCESS;
		return EXIT_FAILURE;
		}
	}
	return EXIT_FAILURE;
}
/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	pid_t pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		exit(1);
	} else if (pid1 == 0) {
		// Child process
		int r = parse_command(cmd1, level, father);

		exit(r);
	}

	pid_t pid2 = fork();

	if (pid2 == -1) {
		perror("fork");
		exit(1);
	} else if (pid2 == 0) {
		// Child process
		int r = parse_command(cmd2, level, father);

		exit(r);
	}

	// Parent process
	int status1, status2;

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WIFEXITED(status1) && WIFEXITED(status2)) {
		// Return the exit status of the both commands
		return WEXITSTATUS(status1) && WEXITSTATUS(status2);
	}

	// Error occurred
	return EXIT_FAILURE;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	// Create pipe
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		perror("pipe");
		exit(EXIT_FAILURE);
	}

	pid_t pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else if (pid1 == 0) {
		// Child process for command1
		// Close unused read end of the pipe
		close(pipefd[PIPE_READ]);
		// Redirect stdout to the pipe write end
		dup2(pipefd[PIPE_WRITE], STDOUT_FILENO);
		// Execute command
		int stat = parse_command(cmd1, level, father);

		// Exit with the status of the command
		exit(stat);
	}

	pid_t pid2 = fork();

	if (pid2 == -1) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else if (pid2 == 0) {
		// Child process for command2
		// Close unused write end of the pipe
		close(pipefd[PIPE_WRITE]);
		// Redirect stdin to the pipe read end
		dup2(pipefd[PIPE_READ], STDIN_FILENO);
		// Execute command
		int stat = parse_command(cmd2, level, father);

		// Exit with the status of the command
		exit(stat);
	}

	// Parent process
	// Close unused ends of the pipe
	close(pipefd[PIPE_READ]);
	close(pipefd[PIPE_WRITE]);

	int status;

	// Wait for both children
	waitpid(pid1, &status, 0);
	waitpid(pid2, &status, 0);

	if (WIFEXITED(status)) {
		// Return the exit status of the last command in the pipeline
		return WEXITSTATUS(status);
	}

	// Error occurred
	return EXIT_FAILURE;
}
/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */
	if (c == NULL)
		return EXIT_SUCCESS;

	if (c->op == OP_NONE) {
		/* Execute a simple command. */
		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level, father);

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) != EXIT_SUCCESS) {
			return parse_command(c->cmd2, level + 1, c);
		}
		break;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		if (parse_command(c->cmd1, level + 1, c) == EXIT_SUCCESS) {
			return parse_command(c->cmd2, level + 1, c);
		}
		break;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level, father);

	default:
		return SHELL_EXIT;
	}

	return EXIT_SUCCESS;
}
