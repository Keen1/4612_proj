import os
#database crawler class
#crawls the directory to find browser history databases
class DbCrawler:

	def find_Browser_History_Databases(self, root_directory):
	    browser_paths = []

	    for root, dirs, files in os.walk(root_directory):
	        if 'places.sqlite' in files:
	            database_path = os.path.join(root, 'places.sqlite')
	            print(f"found db at {database_path}" )
	            browser_paths.append(database_path)

	        if 'History' in files:
	            database_path = os.path.join(root, 'History')
	            if 'Google' in root:
	            	print(f"found db at {database_path}")
	            	browser_paths.append(database_path)
	            elif 'Microsoft' in root and 'Snapshots' not in root:
	            	print(f"found db at {database_path}")
	            	browser_paths.append(database_path)

	    return browser_paths




