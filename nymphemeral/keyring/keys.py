from pkg_resources import resource_listdir, resource_string


def read_default_keys():
    """Read the public keys included in nymphemeral.

    The returned dictionary maps the public keys to the filenames they were
    read from.

    :rtype: dict
    """
    keys = dict()
    for filename in resource_listdir(__name__, '.'):
        if filename.endswith('.asc'):
            keys[filename] = resource_string(__name__, filename)
    return keys
