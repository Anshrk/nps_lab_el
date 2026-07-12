
import os, copy
from dsh import api, shell, node, evaluators, matchers
from flange import cfg



def __make_child_context(parent_ctx, data):
    newctx = copy.deepcopy(parent_ctx) if parent_ctx else {}
    if 'vars' in data:
        newctx.update(data['vars'])
    return newctx



def node_factory_context(data, name=None, ctx={}):

    if name:
         # a named context is not the root
        rootCmd = node_factory_shell(name, __make_child_context(ctx, data))
    else:
        name = data[api.DSH_MARKER_ELEMENT] if data.get(api.DSH_MARKER_ELEMENT ) else api.DSH_DEFAULT_ROOT
        rootCmd = node.node_root(name, __make_child_context(ctx, data))


    # maintain a tuple in the node context that keeps nested context names
    if rootCmd.context and rootCmd.context.get(api.CTX_VAR_PATH):
        rootCmd.context[api.CTX_VAR_PATH] = rootCmd.context[api.CTX_VAR_PATH] + (name,)
    else:
        rootCmd.context[api.CTX_VAR_PATH] = (name,)

    # Process the remaining keys
    for key, val in data.items():
        # print 'dsh ctx contructr ', key, val
        if key in ['dsh', 'vars', 'include']:
            pass
        elif key == 'contexts':
            for k, v in val.items():
                rootCmd.add_child(node_factory_context(v, k, ctx=rootCmd.context))
        elif key == 'commands':
            for k, v in val.items():
                rootCmd.add_child(node_factory_command(k, v, __make_child_context(rootCmd.context, data)))
        else:
            # print 'visiting ', key, ' as a ctx rather than cmd'
            # if isinstance(val, dict) and not 'do' in val:
            #     print 'attempting ', key, ' as a ctx rather than cmd'
            #     # This is not a valid command node. its mostly likely a context. try it that way
            #     rootCmd.add_child(node_factory_context(val, key, ctx=rootCmd.context))
            # else:
            rootCmd.add_child(node_factory_command(key, val, __make_child_context(rootCmd.context, data)))
    return rootCmd


def node_factory_command(key, val, ctx={}, usage=None):
    """
    handles "#/definitions/type_command"

    :param key:
    :param val:
    :param ctx:
    :return:
    """
    # command can be specified by a simple string
    if isinstance(val, str):
        root = node.CmdNode(key, context=ctx, usage=usage, method_evaluate=evaluators.require_all_children)
        n = node.node_shell_command(key+"_cmdstr", val, ctx=ctx, return_output=False)
        n.match = matchers.match_always_consume_no_input
        root.add_child(n)
        return root

    # command can be a list of commands (nesting allowed)
    elif isinstance(val, list):
        root = node.CmdNode(key, context=ctx, usage=usage, method_evaluate=evaluators.require_all_children)
        # add child cmds
        for i, c in enumerate(val):
            cn = node_factory_command(key+'_'+str(i+1), c, ctx=ctx)
            root.add_child(cn)
            # swallow completions
            cn.match = matchers.match_always_consume_no_input

        return root

    # command can be a dict with keys {do,help,env}
    elif isinstance(val, dict):
        root = node.CmdNode(key, context=ctx, method_evaluate=evaluators.require_all_children)

        newctx = ctx.copy()
        if 'vars' in val:
            newctx.update(val['vars'])

        try:
            cn = node_factory_command(
                key+'_do_dict',
                val['do'],
                ctx=newctx)

            root.add_child(cn)
            # swallow completions
            cn.match = matchers.match_always_consume_no_input
        # cn.evaluate = evaluators.require_all_children
        except Exception as e:
            # replace the root node with an error message echo
            root = node.node_display_message(key, str(e))

        if 'on_failure' in val:
            root.on_failure(node_factory_command(
                key+'_on_failure',
                val['on_failure'],
                ctx=newctx))

        return root

    else:
        raise ValueError("value of command {} must be a string, list, or dict. type is {}".format(key, type(val)))



def node_factory_shell(name, ctx=None):

    def run_as_shell(snode, match_result, child_results):
        # If no child node results are available, then this node is assumed to be
        # at the end of the input and will execute as a interactive subcontext/shell
        matched_input = match_result.matched_input()
        if len(matched_input) == 1 and matched_input[0] == snode.name and not match_result.input_remainder():
            # clone this node as a root node and run it
            cnode = node.node_root(snode.name, snode.context)
            for child in snode.get_children():
                cnode.add_child(child)
                cnode.flange = snode.flange
            return shell.DevShell(cnode).run()

        # If there are children that returned a result, then just pass those on.
        # In this case this node is acting as a container
        if child_results:
            return child_results

    snode = node.CmdNode(name, context=ctx)
    snode.execute = lambda match_result, child_results: run_as_shell(snode, match_result, child_results)
    return snode

