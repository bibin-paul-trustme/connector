import os

"""
Returns the file extensions present in a directory tree.

If the tree contains a .git directory, that directory's contents
are ignored.

Arguments:
    top: the root of the tree

Returns:
    set of strings
"""

def get_extensions_in_tree(top = '.'):

    exts = set()

    for _, dirnames, filenames in os.walk(top):
        if '.git' in dirnames:
            dirnames.remove('.git') # Don't visit .git directories
        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if ext:
                exts.add(ext)

    return exts
