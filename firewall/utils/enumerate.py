from firewall.base.cli_parser import BsCli
from firewall.base.validation import Validation
from firewall.base.config import BWConfig
from firewall.environment.rhel import config
from firewall.utils.shell import Interact
from firewall.utils.shell import Bcolors
from firewall.utils import ipaddr
try:
    from Queue import Queue  # Python 2
except ImportError:
    from queue import Queue  # Python 3
from threading import Thread
try:
    # Python 3
    from queue import Empty as QueueEmpty
except ImportError:  # pragma: no cover
    # Python 2 fallback
    from Queue import Empty as QueueEmpty
import platform
import os
import subprocess
import random



class pingSweep(BsCli):
    def __init__(self, subnet=None, config_in=None, threads=4, shuffle=False, verbose=False):
        super(pingSweep, self).__init__(verbose=verbose)
        if subnet is not None:
            try:
                self.subnet_raw = subnet
                self.subnet = list(ipaddr.IPNetwork(subnet))
            except:
                raise Exception('Please ensure your subnet is in proper format: 192.168.1.0/24')
        self.threads = threads
        self.queue = Queue()
        self.alive = 0
        self.alive_hosts = []
        self.shuffle = random
        self.it = Interact()
        self.root_check = self.it.root_check(debug=False)
        self.parse_args()
        self.config_in = config_in
        self.shuffle = shuffle
        self.verbose=verbose

        print(config_in)
        if config_in is not None:
            self.configs = config(config=config_in, VERBOSE=self.verbose)
            #Validation(config_in, verbose=self.verbose).validate()
            self.target_ranges = self.configs.configs.get('target_range', '')
            self.trusted_range = self.configs.configs.get('trusted_range', '')
            self.nostrike = self.configs.configs.get('nostrike', '')
        else:
            #print("[-] Please specify a configuration path!")
            self.nostrike = None


        self.GREEN_PLUS = "[{green}+{endc}]".format(green=Bcolors.OKGREEN, endc=Bcolors.ENDC)
        self.WARN = "[{red}!{endc}]".format(red=Bcolors.WARNING, endc=Bcolors.ENDC)
        self.INFO = "[{obc}INFO{endc}]".format(obc=Bcolors.OKBLUE, endc=Bcolors.ENDC)

    def shuffle_host(self):
        random.shuffle(self.subnet)
        return self.subnet

    def pinger(self, i, q):
        """PING SUBNET without blocking indefinitely when queue is empty."""
        nostrike = None
        # Prepare no-strike list as strings if configured
        if self.nostrike:
            nostrike = [str(x) for b in self.nostrike for x in ipaddr.IPNetwork(b)]

        # Prepare cross-platform ping command template
        is_windows = platform.system().lower() == 'windows'
        if is_windows:
            # -n 1 one echo, -w 1000 timeout in ms
            ping_tpl = "ping -n 1 -w 1000 %s"
        else:
            # -c 1 one echo, -W 1 timeout in seconds
            ping_tpl = "ping -c 1 -W 1 %s"

        devnull_path = os.devnull

        while True:
            try:
                # Do not block forever; exit when queue is drained
                ip = q.get(timeout=0.1)
            except QueueEmpty:
                break

            try:
                # Skip IPs in nostrike list if provided
                allowed = (not nostrike) or (str(ip) not in nostrike)
                if not allowed:
                    continue

                cmd = ping_tpl % ip
                with open(devnull_path, 'w') as devnull:
                    ret = subprocess.call(
                        cmd,
                        shell=True,
                        stdout=devnull,
                        stderr=subprocess.STDOUT,
                    )

                if ret == 0:
                    print('{gp} {ip} is alive'.format(gp=self.GREEN_PLUS, ip=str(ip)))
                    self.alive += 1
                    self.alive_hosts.append(str(ip))
            finally:
                # Always notify the queue that the task is processed
                q.task_done()
        return

    # Spawn thread pool
    def thread_pool(self):
        for i in range(self.threads):
            worker = Thread(target=self.pinger, args=(i, self.queue))
            worker.setDaemon(True)
            worker.start()
        return

    def queue_workers(self):
        for ip in self.subnet:
            self.queue.put(ip)
        return

    def get_alive(self):
        if self.shuffle:
            self.shuffle_host()

        self.thread_pool()
        self.queue_workers()
        print(str('{info} Processing {subnet_length} hosts for {subnet} using {x} threads'.format(info=self.INFO, subnet=self.subnet_raw, subnet_length=len(self.subnet), x=self.threads)))
        self.queue.join()
        if self.verbose and self.alive:
            print(str("{gp} {alive} alive hosts in subnet".format(alive=self.alive, gp=self.INFO)))
        if self.verbose and not self.alive:
            print(str("{rm} {alive} alive hosts in subnet".format(alive=self.alive, rm=self.WARN)))
        return self.alive_hosts

# ALLOW PING BY DEFAULT
#ps = pingSweep(subnet='172.16.63.0/24', config_in='/home/assessor/PycharmProjects/firewall/configs/exampleconfig.ini', shuffle=True)