"""
Simple code to fetch data from Github.
"""

from pydriller import Repository
import requests
from pprint import pprint
import base64
from github import Github
import bq_helper
from bq_helper import BigQueryHelper


def helper_print_repo(repo):
    # repository full name
    print("Full name:", repo.full_name)
    # repository description
    print("Description:", repo.description)
    # the date of when the repo was created
    print("Date created:", repo.created_at)
    # the date of the last git push
    print("Date of last push:", repo.pushed_at)
    # home website (if available)
    print("Home Page:", repo.homepage)
    # programming language
    print("Language:", repo.language)
    # number of forks
    print("Number of forks:", repo.forks)
    # number of stars
    print("Number of stars:", repo.stargazers_count)
    print("-"*50)
    """
    # repository content (files & directories)
    print("Contents:")
    for content in repo.get_contents(""):
        print(content)
    
    try:
        # repo license
        print("License:", base64.b64decode(repo.get_license().content.encode()).decode())
    except:
        pass
    """

def data_fetch_drill():
    for commit in Repository('https://github.com/ishepard/pydriller').traverse_commits():

        print("Hash: " + str(commit.hash))
        print("Commit Message: " + str(commit.msg))
        print("Author: " + str(commit.author.name))
        exit(1)
        print(commit.modified_files)

        for file in commit.modified_files:
            print(file.filename, ' has changed')
            exit()


def data_get_github_private_multiple_repositories():
    print("Github Statistics: Private Repositories")
    username = "parichaya"
    url = f"https://api.github.com/users/{username}"
    user_data = requests.get(url).json()
    pprint(user_data)


def data_get_github_public_multiple_repositories():
    print("Github Statistics: Public Repositories")
    username = "parichaya"
    g = Github()
    user = g.get_user(username)

    print("View #1")
    for repo in user.get_repos():
        print("Github Repository [" + str(repo) + "] " + "for user [" + username + "]")

    print("*"*15 +"\n")

    print("View #2")
    for repo in user.get_repos():
        helper_print_repo(repo)
        print("=" * 100)


def data_get_github_public_search():
    topic = "python"
    print("Github Statistics: Public Repositories Search | Topic: ["+str(topic)+"].")
    username = "parichaya"
    g = Github()
    user = g.get_user(username)
    count = 0
    total = 30
    for i, repo in enumerate(g.search_repositories("topic:"+str(topic))):
        helper_print_repo(repo)
        print("=" * 100)
        count += 1
        if i == total-1:
            break
    print("End of Public Repository Search | Count = [" + str(count) + "] | Topic = [" + str(topic) + "].")

def data_libraries_io():
    print("Libraries.io Data")
    library = bq_helper.BigQueryHelper(active_project="bigquery-public-data",
                                       dataset_name="libraries_io")

    bq_assistant = BigQueryHelper("bigquery-public-data", "libraries_io")
    print(bq_assistant.list_tables())
    print(bq_assistant.head("repositories", num_rows=20))
    #print(bq_assistant.table_schema("repositories"))
    print("What are the repositories, avg project size, and avg # of stars?")
    sql_q1 = """
                SELECT
                  host_type,
                  COUNT(*) repositories,
                  ROUND(AVG(size),2) avg_size,
                  ROUND(AVG(stars_count),2) avg_stars
                FROM
                  `bigquery-public-data.libraries_io.repositories`
                GROUP BY
                  host_type
                ORDER BY
                  repositories DESC
                LIMIT
                  1000;
        """
    response1 = library.query_to_pandas_safe(sql_q1)
    print(response1.head(10))
    print("Type: " + str(type(response1)))


    print("What are the top dependencies per platform?")
    sql_q2 = """
                SELECT
                  dependency_platform,
                  COUNT(*) dependencies,
                  APPROX_TOP_COUNT(dependency_name, 3) top_dependencies
                FROM
                  `bigquery-public-data.libraries_io.dependencies`
                GROUP BY
                  dependency_platform
                ORDER BY
                  dependencies DESC;
        """
    response2 = library.query_to_pandas_safe(sql_q2, max_gb_scanned=10)
    print(response2.head(20))

    print("What are the top unmaintained or deprecated projects?")
    sql_q3 = """
                SELECT
                  name,
                  repository_sourcerank,
                  LANGUAGE,
                  status
                FROM
                  `bigquery-public-data.libraries_io.projects_with_repository_fields`
                WHERE
                  status IN ('Deprecated',
                    'Unmaintained')
                ORDER BY
                  repository_sourcerank DESC
                LIMIT
                  20;
        """
    response3 = library.query_to_pandas_safe(sql_q3, max_gb_scanned=10)
    print(response3.head(20))


if __name__ == '__main__':
    #data_fetch_drill()
    #data_get_github_private_multiple_repositories()
    #data_get_github_public_multiple_repositories()
    #data_get_github_public_search()
    data_libraries_io()


