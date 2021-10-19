"""
Simple code to fetch data from Github.
"""

from pydriller import Repository
import requests
from pprint import pprint
import base64
from github import Github


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
    print("Github Statistics: Public Repositories Search")
    username = "parichaya"
    g = Github()
    user = g.get_user(username)
    for i, repo in enumerate(g.search_repositories("topic:npm")):
        helper_print_repo(repo)
        print("=" * 100)
        if i == 9:
            break

if __name__ == '__main__':
    #data_fetch_drill()
    #data_get_github_private_multiple_repositories()
    #data_get_github_public_multiple_repositories()
    data_get_github_public_search()
    pass


