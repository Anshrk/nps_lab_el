
import os, copy
from dsh import api, shell, node, evaluators, matchers
from dsh.node_factory import node_factory_context
from flange import cfg



def get_flange_cfg(
        options=None,
        root_ns=api.DSH_DEFAULT_ROOT,
        base_dir=['.', '~'],
        file_patterns=['.cmd*.yml'],
        file_exclude_patterns=['.history'],
        file_search_depth=2,
        initial_data={}):

    # Insert a default root dsh element in case none of the discovered nodes are at the root
    # level. If no root context exists, then the dsh factory fails to build the node tree
    initial_data.update({root_ns: {api.DSH_MARKER_ELEMENT: root_ns}})

    # Add any explicit values given
    if options:
        initial_data.update(options)


    def update_source_root_path(dsh_root, src):
        '''
        Define a flange source post-processor to set the root path for the source.
        The root path is determined from the value of the api.DSH_MARKER_ELEMENT. This locates
        the source in the tree of dsh nodes/contexts

        :param dsh_root: 'location' of dsh config in the flange data
        :param src: flange source object
        :return: None
        '''

        if not src.contents or not isinstance(src.contents, dict) or api.DSH_MARKER_ELEMENT not in src.contents:
            return

        ns = src.contents.get(api.DSH_MARKER_ELEMENT)
        print(src, 'ns', ns)
        if not ns or not isinstance(ns, str):
            src.root_path = api.DSH_DEFAULT_ROOT

        elif ns.startswith(dsh_root):
            # if the dsh ns starts with the current root, then assume
            # they're referring to the same ns. Just replace separator
            src.root_path = ns.replace('.', api.NS_SEPARATOR)

        else:
            # just append the dsh ns
            src.root_path = dsh_root + api.NS_SEPARATOR + ns.replace('.', api.NS_SEPARATOR)
        # print 'setting {} ns from {} to {}'.format(src.uri, curent_root, src.ns)

        # Add the src location to the vars so context nodes can change cwd
        src.contents['vars' + cfg.DEFAULT_UNFLATTEN_SEPARATOR + api.CTX_VAR_SRC_DIR] = os.path.dirname(src.uri)


    # get flange config. dont pass root_ns so that config that does not
    # contain the 'dsh' element will not fall under dsh root node. If it
    # did then there will more likely be invalid config
    fcfg = cfg.Cfg(
        data=initial_data,
        root_path=None,
        include_os_env=False,
        file_patterns=file_patterns,
        file_exclude_patterns=file_exclude_patterns,
        base_dir=base_dir,
        file_search_depth=file_search_depth,
        src_post_proc=lambda src: update_source_root_path(root_ns, src),
        research=False)

    return fcfg



import click

@click.group(invoke_without_command=True)
@click.option('--base_dir', '-b', multiple=True, default=['~', '.'], 
    help='Base directory to begin search. Mulitple accepted')
@click.option('--file_pattern', '-fp', multiple=True, default=['.dsh*.yml'],
    help='File glob pattern for matching source files. Mulitple accepted')
@click.option('--search_depth', '-sd', default=2,
    help='Depth of directory search starting with base')
@click.option('--ignore_errors', '-ie', is_flag=True, default=False,
    help='Ignore failures to parse matched files. By default, any failure to parse will terminate the shell')
@click.option('--exist_on_init', '-ei', is_flag=True, default=False)
# @click.pass_context
def cli(base_dir,
        file_pattern,
        search_depth,
        ignore_errors,
        exist_on_init):


    f = get_flange_cfg(
        root_ns=api.DSH_DEFAULT_ROOT,
        base_dir= [base_dir] if isinstance(base_dir, str) else base_dir,
        file_patterns=file_pattern,
        file_search_depth=search_depth)

    # from IPython import embed; embed()

    if not [src for src in f.sources if src.parser] :
        print(f'No sources found matching {file_pattern}')
        return 1
       

    # 
    #   Print src info 
    #
    print(f"\n{'sources':<60} ns:")
    for src in [f for f in f.sources if f.uri != 'init_data' and not f.error]:
        ns = str(src.root_path).replace(api.NS_SEPARATOR, '.') if src.root_path else ''
        print(f"{src.uri:60.65} {ns:20}")

    error_sources = [src for src in f.sources if src.error]
    if error_sources:
        print('\nfailed to parse:')
        for src in error_sources:
            print(f"{src.uri:<60} {src.error}")

    if [src for src in f.sources if src.error] and not ignore_errors:
        print('\nExiting due to parse errors. Set --ignore_errors=true to ignore.\n')
        return 1


    #
    #   Construct the tree of nodes that contain all the commands available in the shell
    #
    root_shell = node_factory_context(f.value(api.DSH_DEFAULT_ROOT))
    if not root_shell:
        print('No valid dsh configuration was found')
        return 1


    #
    #   Recursively give each node a reference to the flange object
    #
    def set_flange(n, f):
        n.flange = f
        children = n.get_children()
        for i in range(len(children)):
            # print 'setting flange to ', hex(id(child))
            set_flange(children[i], f)

    set_flange(root_shell, f)


    #
    #   Create and run the interactive shell
    #
    dsh = shell.DevShell(root_shell)
    if exist_on_init:
        return 0
        
    dsh.run()



if __name__ == '__main__':
    cli()
