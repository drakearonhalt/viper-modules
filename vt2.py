import argparse
import glob
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

        self.FUNC_MAP = {'file': {
                            'file_download': self.file_download,
                            'list_tmp': self._display_tmp_files,
                            'delete_tmp': self.delete_tmp,
                            'get_info': self.file_get_info
                        },
                        'retrohunt': {
                            'list': self.retro_list,
                            'list_matches' : self.retro_list_matches
                            }
                        }


        self.subparsers = self.parser.add_subparsers(dest='parser_name')
        self.file_parser = self.subparsers.add_parser('file', help='work with files')
        self.file_parser.add_argument('action', 
                        choices=self.FUNC_MAP['file'].keys(),
                        help='Action to perform on file')
        self.file_parser.add_argument('target',
                        help='hash or filename',
                        default='all')
        self.file_parser.add_argument('-f', '--file',
                        action='store_true',
                        help='read hashes from file, one per line.')

        self.retro_parser = self.subparsers.add_parser('retrohunt', help='interact with retrohunts')
        self.retro_parser.add_argument('action',
                        choices=self.FUNC_MAP['retrohunt'].keys(),
                        help='Action to perform on retrohunt(s)')
        self.retro_parser.add_argument('target',
                        help='ID of retrohunt to act on OR all.') 

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
    
    ##### Copied from orig virustotal

    def _load_tmp_samples(self):
        tmp_samples = []
        samples_path = os.path.join(self.cur_path, 'vt_samples')
        path = os.path.join(samples_path, '*')
        for p in glob.glob(path):
            if os.path.basename(p).isdigit():
                eid = os.path.basename(p)
                fullpath = os.path.join(samples_path, eid, '*')
                for p in glob.glob(fullpath):
                    name = os.path.basename(p)
                    tmp_samples.append((eid, p, name))
            else:
                for p in glob.glob(p):
                    name = os.path.basename(p)
                    if not os.path.basename(p).isdigit():
                        tmp_samples.append(('', p, name))
        return tmp_samples

    def _display_tmp_files(self, args):
        cureid = None
        if __sessions__.is_attached_misp(True):
            cureid = __sessions__.current.misp_event.event.id
        header = ['Sample ID', 'Current', 'Event ID', 'Filename']
        rows = []
        i = 0
        tmp_samples = self._load_tmp_samples()
        if len(tmp_samples) == 0:
            self.log('warning', 'No temporary samples available.')
            return
        for eid, path, name in tmp_samples:
            if eid == cureid:
                rows.append((i, '*', eid, name))
            else:
                rows.append((i, '', eid, name))
            i += 1
        self.log('table', dict(header=header, rows=rows))

    ####

    def file_download(self, args):

        # TODO: switch to zip_file endpoint
        samples_path = os.path.join(self.cur_path, 'vt_samples')
        # for compatibility with original virustotal module
        if __sessions__.is_attached_misp(True):
            samples_path = os.path.join(samples_path, __sessions__.current.misp_event.event.id)
        
        if not os.path.exists(samples_path):
            os.makedirs(samples_path)

        if args.file:
            with open(args.target, 'r') as fd:
                for line in fd:
                    self._download_file(line.strip(), samples_path)
        else:
            self._download_file(args.target, samples_path) 


    def delete_tmp(self, args):
        tmp_samples = self._load_tmp_samples()
        files = []
        if args.target == 'all':
            files = [f[1] for f in tmp_samples]
        else:
            try:
                sample_id = int(self.args.target)
                files = [tmp_samples[sample_id][1]]
            except ValueError:
                self.log('warning', 'Options for delete_tmp are either Sample ID (int) or "all"')
                return
        

        for f in files:
            os.remove(f)
            self.log('success', f'Successfully removed {f}')
            

    def file_get_info(self, args):
        if args.target == 'current':
            if __sessions__.is_attached_file():
                filehash = __sessions__.current.file.sha256
            else:
                self.log('warning', 'Must have a current session to use "current" target.')
                return
        else:
            filehash = args.target

        try:
            fileobj = self.vt_client.get_object(f'/files/{filehash}')
        except vt.APIError as e:
            self.log('error', e.message)

        #print(dir(fileobj))
        self.log('success', 'VirusTotal File Data\n')

        # hashes
        self.log('item', f'Filename:\t{fileobj.meaningful_name}')
        self.log('item', f'md5:\t\t{fileobj.md5}')
        self.log('item', f'sha1:\t{fileobj.sha1}')
        self.log('item', f'sha256:\t{fileobj.sha256}')
        self.log('item', f'ssdeep:\t{fileobj.ssdeep}')
        self.log('item', f'vhash:\t{fileobj.vhash}\n')

        if hasattr(fileobj, 'signature_info'):
            
            self.log('success', 'Signature Information')
            self.log('item', f'Signers:\t{fileobj.signature_info["signers"]}')
            signers = fileobj.signature_info['signers details']
            for s in signers:
                self.log('item', f'Name:\t{s["name"]}')
                self.log('item', f'Issuer:\t{s["cert issuer"]}')
                self.log('item', f'Status:\t{s["status"]}')
                self.log('item', f'Valid Usage:\t{s["valid usage"]}\n')
        else:
            self.log('info', 'File not signed\n')

        # submission/first seen 
        header = ['First Submission Data', 'Last Submission Date',
                    'Times Submitted','Unique Sources', 'Type', 'Size']
        rows = [[ fileobj.first_submission_date,
                    fileobj.last_submission_date,
                    fileobj.times_submitted,
                    fileobj.unique_sources,
                    fileobj.type_tag,
                    fileobj.size]]
        self.log('table', dict(header=header, rows=rows))
        print()
       
        # print last analysis stats
        self.log('success', 'Last Analysis Stats:')
        header = list(fileobj.last_analysis_stats.keys())
        rows = [list(fileobj.last_analysis_stats.values())]
        self.log('table', dict(header=header, rows=rows))
        print()

    def retro_list(self, args):
        # TODO: pass limit and batch_size args 
        retro_jobs = self.vt_client.iterator('/intelligence/retrohunt_jobs',
        limit=10, batch_size=10)
        header = ['ID', 'Created','Finished', 'Matches', 'Corpus', 'Status']
        rows = []
        for r in retro_jobs:
            rows.append([r.id, r.creation_date, r.finish_date, r.num_matches,
            r.corpus, r.status])

        self.log('table', dict(header=header, rows=rows))

    def retro_list_matches(self, args):
        # TODO: option to write to csv? 
        try: 
            matching_files = self.vt_client.iterator(f'/intelligence/retrohunt_jobs/{args.target}/matching_files',
                    batch_size=10, limit=30)
        except vt.APIError as e:
            self.log('error', e.message)
            return

        header = ['SHA256', 'Rule Name', 'Detections', 'Size','Type' ,'First Seen', 'Last Seen', 'Submitters']
        rows = []
        for m in matching_files:
            c = m.context_attributes
            rows.append([m.sha256, c['rule_name'], m.last_analysis_stats['malicious'],
                    m.size, m.type_tag, m.first_submission_date, m.last_submission_date, m.unique_sources]) 
             
        self.log('table', dict(header=header, rows=rows))
            


    def  run(self):

        super(VirusTotal2, self).run()
        if self.args is None:
            return

        # Call appropriate function
        self.FUNC_MAP[self.args.parser_name][self.args.action](self.args)
        
        if not HAVE_VT:
            self.log('error', "Missing dependency, install virustotal-api (`pip install virustotal-api`)")
            return


