import os
import configparser
config = configparser.ConfigParser()
config.read('svn_config.ini')

def detect_frameworks_in_directory(root_directory):
    frameworks = {}
    total_files = 0

    for root, dirs, files in os.walk(root_directory):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for file in files:
            if file.startswith('.'):
                continue
            total_files += 1
            file_path = os.path.join(root, file)

            if file == 'requirements.txt'  or file.endswith('.py'):
                frameworks['Python'] = frameworks.get('Python', 0) + 1

            elif file.endswith(('.sln', '.csproj')):
                frameworks['.NET'] = frameworks.get('.NET', 0) + 1

            elif file in ('pom.xml',) or file.endswith('build.gradle') or file.endswith(('.class', '.java')): 
                frameworks['Java'] = frameworks.get('Java', 0) + 1

            elif file in ('package.json',) or file.endswith(('.js', '.jsx')):
                frameworks['JavaScript'] = frameworks.get('JavaScript', 0) + 1

            elif file.endswith('.ts'):
                frameworks['TypeScript'] = frameworks.get('TypeScript', 0) + 1

            elif file.endswith('.go'):
                frameworks['Go'] = frameworks.get('Go', 0) + 1

            elif file.endswith(('.php', '.php3', '.php4', '.php5', '.phtml')):
                frameworks['PHP'] = frameworks.get('PHP', 0) + 1

            elif file.endswith('.cls-meta.xml'):
                frameworks['Apex'] = frameworks.get('Apex', 0) + 1

            elif file in ('Gemfile',):
                frameworks['Ruby'] = frameworks.get('Ruby', 0) + 1

            elif file in ('composer.json',):
                frameworks['PHP'] = frameworks.get('PHP', 0) + 1

            elif file.endswith('.kt'):
                frameworks['Kotlin'] = frameworks.get('Kotlin', 0) + 1

    frameworks_with_percentage_check = {'Python', 'Java', 'JavaScript', 'TypeScript', 'Go', 'PHP', 'Kotlin'}
    framework_percentages = {framework: (count / total_files) * 100 for framework, count in frameworks.items()}
    lang_list = set()
    for framework, percentage in framework_percentages.items():
        if framework in frameworks_with_percentage_check:
            if percentage > 1:
                lang_list.add(framework)
        else:
            lang_list.add(framework)
    return list(lang_list)

repo_list = config.get('LOCAL', 'repo_list').split(', ')
for repo in repo_list:
    if repo.endswith('/'):
        folder_name = repo.split('/')[-2]
    else:
        folder_name = repo.split('/')[-1]
    detected_frameworks = detect_frameworks_in_directory(folder_name)
    print(repo , detected_frameworks)
# print(detected_frameworks)
# if detected_frameworks == 'java':
#     existing_values = config.get('LOCAL', 'java_repo_list').split(', ')
#     existing_values.extend(new_values)
#     updated_value_string = ', '.join(existing_values)
#     config.set('LOCAL', 'java_repo_list', updated_value_string)
# elif detected_frameworks == '.NET':
#     existing_values = config.get('LOCAL', 'dotnet_repo_list').split(', ')
#     existing_values.extend(new_values)
#     updated_value_string = ', '.join(existing_values)
#     config.set('LOCAL', 'java_repo_list', updated_value_string)
#     with open('svn_config.ini', 'w') as configfile:
#         config.write(configfile)

