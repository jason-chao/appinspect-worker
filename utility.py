import hashlib
import os
import shutil

class Utility():
    def get_all_files_in_dir(root_dir: str):
        """Traverse a directory tree and find all the files.
            Args:
                root_dir: The directory to traverse
            Returns:
                A list of full filenames for the files
        """
        file_list = []
        for (dir_path, _, filenames) in os.walk(root_dir):
            for filename in filenames:
                file_list.append(os.path.join(dir_path, filename))
        return file_list

    def remove_file_or_dir_if_exists(path: str):
        """Remove a file or a dir if the path exists
            Args:
                path: The path to the file or dir to be removed
            Returns:
                None
        """
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)

    
    def get_file_hash_sha256(filename: str):
        """Get the sha256 hash of a file
            Args:
                path: The path to the file to be computed to get a sha256 hash
            Returns:
                None
        """
        hash = None
        with open(filename, "rb") as f:
            content_blob = f.read()
            hash = hashlib.sha256(content_blob).hexdigest()
        return hash

