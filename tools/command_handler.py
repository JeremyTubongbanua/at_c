class CommandHandler(object):
  def __init__(self, platform, framework, root_dir):
    self.platform = platform
    self.framework = framework
    self.dir_name = platform + '_' + framework
    self.root_dir = root_dir
    pass
  def handle(self, command, args):
    if command == 'init': self.init(args)
    elif command == 'build': self.build(args)
    elif command == 'clean': self.clean(args)
    elif command == 'project': self.project(args)
    else: raise Exception('Unknown command: ' + command)
    pass
  def init(self, args):
    raise Exception('Not implemented')
    pass
  def build(self, args):
    if args.clean: self.clean(args)
    pass
  def _copy_build(self, args):
    if args.output is None: pass
    from glob import glob
    from shutil import copy
    from os import path
    output_dir = path.dirname(args.output)
    for lib in glob(self.root_dir+'/lib/'+self.dir_name+'/lib*.a'):
      copy(lib, output_dir)
    print('Library files copied to ' + output_dir)
    pass
  def clean(self, args):
    from shutil import rmtree
    rmtree(self.root_dir+'/build/'+self.dir_name, ignore_errors=True)
    rmtree(self.root_dir+'/lib/'+self.dir_name, ignore_errors=True)
    print('Done cleaning!')
    pass
  def project(self, args):
    from distutils.dir_util import copy_tree
    from os import path
    project_path = args.project_path
    project_name = path.basename(project_path)
    print('Creating project '+project_name+'...')
    copy_tree(self.root_dir+'/archetypes/'+self.dir_name, project_path)
    return project_path, project_name