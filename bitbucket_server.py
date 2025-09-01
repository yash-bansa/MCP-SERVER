import os
import requests
from requests.auth import HTTPBasicAuth
import traceback
from typing import Any
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from starlette.responses import Response, JSONResponse
import logging
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
import uvicorn 
import traceback
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer 
from jose import JWTError, jwt 
from passlib.context import CryptContext 
from datetime import datetime, timedelta 
from typing import List, Dict 
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    filename='server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("bitbucket")

BITBUCKET_USERNAME = os.getenv("BITBUCKET_USERNAME", "")
BITBUCKET_APP_PASSWORD = os.getenv("BITBUCKET_APP_PASSWORD", "")
@mcp.tool()
def list_bitbucket_workspaces() -> List[str]:
    """
    List all Bitbucket workspaces accessible to the authenticated user.

    Returns
    -------
    List[str]
        A list of workspace slugs (workspace IDs) from Bitbucket.
    """

    url = "https://api.bitbucket.org/2.0/workspaces"
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    try:
        logger.info("Sending request to Bitbucket API to list workspaces.")
        response = requests.get(
            url,
            auth=HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD),
            headers=headers,
            timeout=10
        )
        print(f"Response status code: {response.status_code}, {response.text}")
        #response.raise_for_status()  # Raise HTTPError for 4xx/5xx

        data = response.json()
        workspaces = [ws.get("slug", "") for ws in data.get("values", []) if "slug" in ws]
        logger.info(f"Retrieved {len(workspaces)} workspaces.")

        return workspaces

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err} - Response: {response.text}")
        raise RuntimeError(f"Failed to fetch workspaces: {http_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Request error occurred: {req_err}")
        raise RuntimeError(f"Request failed: {req_err}")
    except Exception as e:
        logger.exception("Unexpected error while listing workspaces.")
        raise RuntimeError(f"Unexpected error: {e}")
    

@mcp.tool()
def list_bitbucket_repositories(workspace: str) -> List[str]:
    """
    List all repositories under a specified Bitbucket workspace.

    Parameters
    ----------
    workspace : str
        The Bitbucket workspace slug (e.g., "myteam123").

    Returns
    -------
    List[str]
        A list of repository names under the given workspace.

    Raises
    ------
    RuntimeError
        If the API request fails due to HTTP or network errors.
    EnvironmentError
        If required environment variables are not set.
    ValueError
        If the response does not contain expected repository data.
    """

    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}"
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    try:
        logger.info(f"Fetching repositories for workspace: {workspace}")
        response = requests.get(
            url,
            auth=HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD),
            headers=headers,
            timeout=10
        )
        response.raise_for_status()

        data = response.json()
        if "values" not in data:
            raise ValueError("Unexpected response format: 'values' key missing.")

        repositories = [repo.get("name", "") for repo in data["values"] if "name" in repo]
        logger.info(f"Retrieved {len(repositories)} repositories from workspace '{workspace}'.")

        return repositories

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err} - Response: {response.text}")
        raise RuntimeError(f"Failed to fetch repositories: {http_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Request error occurred: {req_err}")
        raise RuntimeError(f"Request failed: {req_err}")
    except Exception as e:
        logger.exception("Unexpected error while listing repositories.")
        raise RuntimeError(f"Unexpected error: {e}")

@mcp.tool()
def get_file_content_from_bitbucket(workspace: str, repo_slug: str, commit: str, path: str) -> str:
    """
    Retrieve the content of a specific file from a Bitbucket repository.

    Parameters
    ----------
    workspace : str
        The Bitbucket workspace slug (e.g., "myteam123").
    repo_slug : str
        The repository slug (usually the repo name in lowercase with dashes).
    commit : str
        The commit hash or branch name (e.g., "main").
    path : str
        The path to the file in the repository (e.g., "src/app.py").

    Returns
    -------
    str
        The raw content of the file as a string.

    Raises
    ------
    RuntimeError
        If the API request fails due to HTTP or network issues.
    FileNotFoundError
        If the file does not exist in the given repo/commit/path.
    EnvironmentError
        If credentials are missing.
    """

    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/src/{commit}/{path}"
    headers = {
        'Accept': 'application/octet-stream'
    }

    try:
        logger.info(f"Fetching file content from {workspace}/{repo_slug} at {commit}:{path}")
        response = requests.get(
            url,
            auth=HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD),
            headers=headers,
            timeout=10
        )
        if response.status_code == 404:
            logger.warning(f"File not found: {path} at commit {commit} in repo {repo_slug}")
            raise FileNotFoundError(f"File not found: {path} at {commit} in repo {repo_slug}")
        response.raise_for_status()

        content = response.text
        logger.info(f"Successfully fetched file of size {len(content)} bytes.")
        return content

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error: {http_err} - Response: {response.text}")
        raise RuntimeError(f"Failed to fetch file content: {http_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Network error: {req_err}")
        raise RuntimeError(f"Request failed: {req_err}")
    except Exception as e:
        logger.exception("Unexpected error while retrieving file.")
        raise RuntimeError(f"Unexpected error: {e}")

@mcp.tool()
def list_bitbucket_commits(workspace: str, repo_slug: str, branch: str = "main", limit: int = 10) -> List[Dict[str, str]]:
    """
    List recent commits from a Bitbucket repository.

    Parameters
    ----------
    workspace : str
        The Bitbucket workspace slug (e.g., "myteam123").
    repo_slug : str
        The repository slug (e.g., "my-repo").
    branch : str, optional
        The branch to list commits from (default is "main").
    limit : int, optional
        Maximum number of commits to return (default is 10, max is 100).

    Returns
    -------
    List[Dict[str, str]]
        A list of commits, each containing hash, message, and date.

    Raises
    ------
    RuntimeError
        For API errors or network failures.
    EnvironmentError
        If credentials are missing.
    """

    url = f"https://api.bitbucket.org/2.0/repositories/{workspace}/{repo_slug}/commits/{branch}"
    headers = {
        'Accept': 'application/json'
    }
    params = {
        'pagelen': min(limit, 100)
    }

    try:
        logger.info(f"Fetching up to {limit} commits from {workspace}/{repo_slug} on branch '{branch}'")
        response = requests.get(
            url,
            auth=HTTPBasicAuth(BITBUCKET_USERNAME, BITBUCKET_APP_PASSWORD),
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()

        data = response.json()
        commits = [
            {
                "hash": commit.get("hash", "")[:10],
                "message": commit.get("message", "").strip(),
                "date": commit.get("date", "")
            }
            for commit in data.get("values", [])
        ]

        logger.info(f"Retrieved {len(commits)} commits.")
        return commits

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err} - Response: {response.text}")
        raise RuntimeError(f"Failed to fetch commits: {http_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Request error occurred: {req_err}")
        raise RuntimeError(f"Request failed: {req_err}")
    except Exception as e:
        logger.exception("Unexpected error while listing commits.")
        raise RuntimeError(f"Unexpected error: {e}")
    
transport = SseServerTransport("/messages/")



async def handle_sse(request: Request):
    try:
        logger.info("Handling SSE connection...")
        async with transport.connect_sse(request.scope, request.receive, request._send) as (in_stream, out_stream):
            await mcp._mcp_server.run(in_stream, out_stream, mcp._mcp_server.create_initialization_options())
        return Response(status_code=204)
    except Exception as e:
        logger.error("SSE error: " + traceback.format_exc())
        return JSONResponse(content={"error": "Internal Server Error", "details": str(e)}, status_code=500)


sse_app = Starlette(
    routes=[
        Route("/sse", handle_sse, methods=["GET"]),
        Mount("/messages/", app=transport.handle_post_message),
    ]
)

app = FastAPI()
app.mount("/stream", sse_app)

@app.get("/liveness")
async def liveness():
    """
    Liveness Probe - is the app running?
    - Should return HTTP 200 if alive.
    - Do not put heavy logic here.
    """
    return {"status": "alive"}

@app.get("/readiness")
async def readiness():
    """
    readiness check endpoint to verify server status.
    """
    return {"status": "ready"}

if __name__ == "__main__":
   print("inside the main")
   uvicorn.run(app, host="127.0.0.1", port=8000) 