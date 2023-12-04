/* Reference: */


//16KB chunk size 
#define MAX_XFPR_BUF_SIZE 16384
//#define DEBUG 1

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h> 
#include <getopt.h>
#include <unistd.h>
#include <dirent.h>
#include <assert.h>

void print_usage();
int verify_knownhost(ssh_session session);
int show_remote_processes(ssh_session session);
int sftp_list_dir(ssh_session my_ssh_session, sftp_session sftp, char *dirPathS);
int create_directory(ssh_session my_ssh_session, sftp_session sftp, char *dir_name);
int transfer_file(ssh_session my_ssh_session, sftp_session sftp, int send_file, int read_file, char *dirPathS, char *dirPathC);

int fcount = 0;
char *dirPathC = "/home/kai/Desktop/test";
char *dirPathS =  "/home/ubuntu/Desktop/test";

int main(int argc, char *argv[])
{
	int opt = 0;
	char *ip_addr, *user_name, *password;
	int long_index = 0;
	
    ssh_session	my_ssh_session;
	sftp_session sftp;
    int             port = 22, send_file = 0, read_file = 0, lst_dir = 0;
    int             rc;

	
	static struct option long_options[] = {
		{"ip_address",	required_argument,	0,	'i'},
		{"user_name",	required_argument,	0,	'u'},
		{"port_num",	required_argument,	0,	'p'},
		{"send_file",	required_argument,	0,	's'},
		{"read_file",	required_argument,	0,	'r'},
		{"get_passw",	required_argument,	0,	'g'},
		{"list_dir",	required_argument,	0,	'l'},
		{0,	0,	0,	0}
	};
	while((opt = getopt_long(argc, argv, "i:u:p:s:r:g:l:", long_options, &long_index)) != -1)
	{
		switch(opt)
		{
			case 'i' : ip_addr = optarg;
				break;
			case 'u' : user_name = optarg;
				break;
			case 'p' : port = atoi(optarg); 
				printf("port: %d\n", port);
				break;
			case 's' : send_file = atoi(optarg);
				break;
			case 'r' : read_file = atoi(optarg);
				break;
			case 'g' : password = optarg;
				printf("password: %s\n", password);
				break;
			case 'l' : lst_dir = atoi(optarg);
				break;
			default: print_usage();
				exit(EXIT_FAILURE);
				break;
		}
	}
	
    /* Creating the session and setting options */
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL) {
        exit(-1);
    }

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, ip_addr); 
    //ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user_name);

    /* Connecting to the server */
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    /* Authenticating the server */
    if (verify_knownhost(my_ssh_session) < 0) {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    /* Authenticate ... */
    //password = getpass("Password: ");
    rc = ssh_userauth_password(my_ssh_session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
	
    /************************/
    #if defined(DEBUG)
		fprintf(stderr, "connect success!\n");
	#endif
	
    show_remote_processes(my_ssh_session);

    /************************/
	
	/* initialize an sftp_session */
	sftp = sftp_new(my_ssh_session);
	if(sftp == NULL)
	{
		fprintf(stderr, "Error allocating SFTP session: %s\n",
			ssh_get_error(my_ssh_session));
	}
	rc = sftp_init(sftp);
	if(rc != SSH_OK)
	{
		fprintf(stderr, "ERROR initializing SFTP session: %x.\n",
		sftp_get_error(sftp));
		sftp_free(sftp);
	}
	else printf( "SFTP Initialized! \n");
	

	/************************/
	if((read_file == 1) && (send_file) == 1)
	{
		printf("cannot simultaneously have send and read\n");
	}
	else 
	{
		transfer_file(my_ssh_session, sftp, send_file, read_file, dirPathS, dirPathC);
	}
	printf("total number of files: %d\n", fcount);
	/************************/
	if(lst_dir)
	{
		sftp_list_dir(my_ssh_session, sftp, dirPathS);
	}
	/************************/

	sftp_free(sftp);
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    exit(0);
}

int verify_knownhost(ssh_session session)
{
    // int             state, hlen;
    unsigned char  *hash = NULL;
    char           *hexa;
    char            buf[10];
	
	int state;
	size_t hlen;
	ssh_key srv_pubkey;
	int rc;
	
    /* look into the known host file */
    state = ssh_is_server_known(session);

	rc = ssh_get_publickey(session, &srv_pubkey);
	if(rc < 0)
	{
		return -1;
	}
	
    /* get a binary version of the public key hash value */
    rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hlen);
	ssh_key_free(srv_pubkey);
	if(rc < 0)
	{
		return -1;
	}

    switch(state) {
        case SSH_SERVER_KNOWN_OK:
            break; /* OK */

        case SSH_SERVER_KNOWN_CHANGED:
            fprintf(stderr, "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
			ssh_clean_pubkey_hash(&hash);
			fprintf(stderr, "For security reasons, connection will be stopped\n");
            return -1;

        case SSH_SERVER_FOUND_OTHER:
            fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
            fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            //free(hash);
            return -1;

        case SSH_SERVER_FILE_NOT_FOUND:
            fprintf(stderr, "Could not find known host file.\n");
            fprintf(stderr, "If you accept the host key here, the file will be"
                    "automatically created.\n");
            /* fallback to SSH_SERVER_NOT_KNOWN */

        case SSH_SERVER_NOT_KNOWN:
            /* Convert a buffer into a colon separated hex string */
            hexa = ssh_get_hexa(hash, hlen);
            fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
            fprintf(stderr, "Public key hash: %s\n", hexa);
            //free(hexa);
			ssh_string_free_char(hexa);

            if(fgets(buf, sizeof(buf), stdin) == NULL) {
                //free(hash);
				ssh_clean_pubkey_hash(&hash);
                return -1;
            }

            if (strncasecmp(buf, "yes", 3) != 0) {
                //free(hash);
				ssh_clean_pubkey_hash(&hash);
                return -1;
            }
			fprintf(stderr, "This new key will be written on disk for further usage. do you agree ?\n");
			if(fgets(buf, sizeof(buf), stdin) == NULL)
			{
				ssh_clean_pubkey_hash(&hash);
				return -1;
			}
			if(strncasecmp(buf, "yes", 3) == 0)
			{
				if(ssh_write_knownhost(session) < 0)
				{
					ssh_clean_pubkey_hash(&hash);
					fprintf(stderr, "error %s\n", strerror(errno));
				}
				return -1;
			}
			
			break;

        case SSH_SERVER_ERROR:
			ssh_clean_pubkey_hash(&hash);
            fprintf(stderr, "Error %s",ssh_get_error(session));
            //free(hash);
            return -1;
    }

    //free(hash);
	ssh_clean_pubkey_hash(&hash);
    return 0;
}

int show_remote_processes(ssh_session session)
{
    ssh_channel channel;
    int         rc;
    char        buffer[256];
    int         nbytes;

    /* Allocate a new channel */
    channel = ssh_channel_new(session);
    if (channel == NULL) {
        return SSH_ERROR;
    }

    /* Open session channel */
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    /* Run a shell command without an interactive shell */
    rc = ssh_channel_request_exec(channel, "pwd"); //show current dir
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }
    
    /* Reads data from a channel */
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0) {
        if (write(1, buffer, nbytes) != (unsigned int)nbytes) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    if (nbytes < 0) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    /* Send an end of file on the channel */
    ssh_channel_send_eof(channel);
    /* Close a channel */
    ssh_channel_close(channel);
    /* Close and free a channel */
    ssh_channel_free(channel);

    return SSH_OK;
}

int sftp_list_dir(ssh_session my_ssh_session, sftp_session sftp, char *dirPathS)
{
	sftp_dir dir;
	sftp_attributes attributes;
	int rc;
	
	dir = sftp_opendir(sftp, dirPathS);
	if(!dir)
	{
		fprintf(stderr, "Directory not opened: %s\n", ssh_get_error(my_ssh_session));
		return SSH_ERROR;
	}
	printf("Name\t\t\tSize\t Perms\t  Owner\t	Group\n");
	
	while((attributes = sftp_readdir(sftp, dir)) != NULL)
	{
		printf("%-20s %.10llu %.8o %s(%d)\t%s(%d)\n", 
			attributes->name,
			(long long unsigned int) attributes->size,
			attributes->permissions,
			attributes->owner,
			attributes->uid,
			attributes->group,
			attributes->gid);

			sftp_attributes_free(attributes);
	}
	if(!sftp_dir_eof(dir))
	{
		fprintf(stderr, "Can't list directory: %s\n", 
			ssh_get_error(my_ssh_session));
		sftp_closedir(dir);
		return SSH_ERROR;		
	}
	rc = sftp_closedir(dir);
	if(rc != SSH_OK)
	{
		fprintf(stderr, "Can't close directory: %s\n",
			ssh_get_error(my_ssh_session));
		return rc;
	}
	return SSH_OK;
}


void print_usage()
{
	printf("Usage: -i: ip_addr -u: user_name -p: port -s: send_file? -r: read_file? -g: password -l: list directory?\n");
}

int create_directory(ssh_session my_ssh_session, sftp_session sftp, char *dir_name)
{
	int rc;
	rc = sftp_mkdir(sftp, dir_name ,S_IRWXU); 
	if(rc != SSH_OK)
	{
		if(sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS)
		{
			fprintf(stderr, "Can't create directory: %s\n",
				   ssh_get_error(my_ssh_session));
			return rc;
		}
	}
	#if defined(DEBUG)
		printf("Create Directory Success! \n");
	#endif
	return SSH_OK;
}

int transfer_file(ssh_session my_ssh_session, sftp_session sftp, int send_file, int read_file, char *dirPathS, char *dirPathC)
{
	//common
	int access_type = O_WRONLY | O_CREAT | O_TRUNC; 
	char pathC[512];
	char pathS[512];
	
	//sendfile
	int rc, nwritten;
	/* declare file access type */
	sftp_file file;
	void *bufferS[MAX_XFPR_BUF_SIZE];
	int inft, fileread;
	struct dirent *filename;
	DIR *dir;
	
	//readfile
	int nbytes;
	int fd;
	void *buffer[MAX_XFPR_BUF_SIZE];

	sftp_dir dirS;
	sftp_attributes attributes;
	
	if(send_file)
	{
		assert(dirPathC != NULL);
		dir = opendir(dirPathC);
		if(dir == NULL)
		{
			printf("open dir %s error!\n", dirPathC);
			exit(1);
		}
		while((filename = readdir(dir)) != NULL)
		{
			if(strcmp(filename->d_name, ".") == 0 || (strcmp(filename->d_name, "..") == 0))	
				continue;
			sprintf(pathC, "%s/%s", dirPathC, filename->d_name);
			sprintf(pathS, "%s/%s", dirPathS, filename->d_name);
			
			struct stat s;
			lstat(pathC, &s);
			if(S_ISDIR(s.st_mode))
			{
				create_directory(my_ssh_session, sftp, pathS);
				transfer_file(my_ssh_session, sftp, send_file, read_file, pathS, pathC);
			}
			else
			{
				inft = open(pathC, O_RDONLY);
				file = sftp_open(sftp, pathS, access_type, S_IRWXU); 
				if(file == NULL)
				{
					fprintf(stderr, "Can't open file for writing: %s\n",
						   ssh_get_error(my_ssh_session));	
					return SSH_ERROR;
				}
				for(;;)
				{
					fileread = read(inft, bufferS, sizeof(bufferS));
					if(fileread == 0)
					{
						break;
					}
					else if(fileread < 0)
					{
						printf("error while reading\n");
						close(inft);
						break;
					}
					nwritten = sftp_write(file, bufferS, fileread);
				}
				close(inft);
		
				rc = sftp_close(file);
				if(rc != SSH_OK)
				{
					fprintf(stderr, "Can't write data to the written file: %s\n",
						   ssh_get_error(my_ssh_session));
					return rc;
				}
				#if defined(DEBUG)
					printf("%d. %s\n", ++fcount, filename->d_name);
				#else
					++fcount;
				#endif
				#if defined(DEBUG)
					printf("send file success!\n");
				#endif
			}
		}
		closedir(dir);
		
		return SSH_OK;
	}
	
	if(read_file)
	{
		assert(dirPathC != NULL);
		access_type = O_RDONLY;
		dirS = sftp_opendir(sftp, dirPathS);
		if(!dirS)
		{
			fprintf(stderr, "Directory not opened: %s\n", ssh_get_error(my_ssh_session));
			return SSH_ERROR;
		}
		while((attributes = sftp_readdir(sftp, dirS)) != NULL)
		{	
			if(strcmp(attributes->name, ".") == 0 || (strcmp(attributes->name, "..") == 0))
				continue;
			
			sprintf(pathC, "%s/%s", dirPathC, attributes->name);
			sprintf(pathS, "%s/%s", dirPathS, attributes->name);
			
			if(sftp_opendir(sftp, pathS)) 
			{
				mkdir(pathC, 0700);
				transfer_file(my_ssh_session, sftp, send_file, read_file, pathS, pathC);
			}
			else
			{
				file = sftp_open(sftp, pathS, access_type, 0);
				if(file == NULL)
				{
					fprintf(stderr, "Can't open file for reading: %s\n",
						ssh_get_error(my_ssh_session));	
					return SSH_ERROR;
				}
				fd = open(pathC, O_CREAT | O_WRONLY, 0777); 
				if(fd < 0)
				{
					fprintf(stderr, "Can't open file for writing: %s\n",
						strerror(errno));	
					return SSH_ERROR;
				}
				for(;;)
				{
					nbytes = sftp_read(file, buffer, sizeof(buffer));
					if(nbytes == 0)
					{
						break; //EOF
					}
					else if(nbytes < 0)
					{
						fprintf(stderr, "Error while reading file: %s\n",
							ssh_get_error(my_ssh_session));
						sftp_close(file);
						return SSH_ERROR;
					}
					nwritten = write(fd, buffer, nbytes);
					if(nwritten != nbytes)
					{
						fprintf(stderr, "Error writing: %s\n",
							strerror(errno));
						sftp_close(file);
						return SSH_ERROR;
					}
				}
				close(fd);
				rc = sftp_close(file);
				if(rc != SSH_OK)
				{
					fprintf(stderr, "Can't close the read file: %s\n",
						ssh_get_error(my_ssh_session));
					return rc;
				}
				
				#if defined(DEBUG)
					printf("read file success!\n");
				#endif
				#if defined(DEBUG)
					printf("%d. %s\n", ++fcount, attributes->name);
				#else
					++fcount;
				#endif
			}
			sftp_attributes_free(attributes);
		}
		sftp_closedir(dirS);
	}
	return SSH_OK;
}
