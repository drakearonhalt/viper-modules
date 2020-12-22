import argparse
import logging
import os

try:
    import vt
    
    HAVE_VT = True
except ImportError:
    HAVE_VT = False

from viper.common.abstracts import Module
from viper.core.config import __config__
from viper.core.project import __project__
from viper.core.session import __sessions__

log = logging.getLogger('viper')

cfg = __config__
cfg.parse_http_client(cfg.virustotal)

class VirusTotal2(Module):
    cmd = 'vt2'
    description = 'Interact with VirusTotal V3 API.'
    authors = ['drakearonhalt']


    def __init__(self):
        super(VirusTotal2, self).__init__()
        if not HAVE_VT:
            self.log('error', "Missing dependency, install vt-py (`pip install vt-py`)")
            return
        self.cur_path = __project__.get_path()
        
        if cfg.virustotal.virustotal_key:
            self.vt_client = vt.Client(cfg.virustotal.virustotal_key)

        
        self.subparsers = self.parser.add_subparsers()
        self.download_parser = self.subparsers.add_parser('download', help='download a file')
        self.download_parser.add_argument('target', help='either a hash or file name')
        self.download_parser.add_argument('-f', '--file',
                        action='store_true',
                        help='read hashes from file, one per line.')
        self.download_parser.set_defaults(func=self.download)
        #self.parser.add_argument('-d', '--download', help='Hash of the file to download')

    def __del__(self):
        self.vt_client.close()

    def _download_file(self, filehash, samples_path):
        filename = os.path.join(samples_path, filehash)
        if os.path.exists(filename):
            self.log('info', '{} has already been downloaded.'.format(filehash))
            return

        with open(filename, 'wb') as fd:
            self.vt_client.download_file(filehash, fd)


        self.log('success', 'Successfully downloaded {}'.format(filehash))

    def download(self, args):
        
        samples_path = os.path.join(self.cur_path, 'vt_samples')
        # for compatibility with original virustotal module
        if __sessions__.is_attached_misp(True):
            samples_path = os.path.join(samples_path, __sessions__.current.misp_event.event.id)
        
        if not os.path.exists(samples_path):
            os.makedirs(samples_path)

        if args.file:
            with open(args.target, 'r') as fd:
                for line in fd:
                    self._download_file(line.strip())
        else:
            self._download_file(args.target, samples_path) 


    def run(self):

        super(VirusTotal2, self).run()
        if self.args is None:
            return

        # call the default function from args
        self.args.func(self.args)
        
        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return


