## ScanSuite Command Line Tool

This tool allows to interact with ScanSuite server remotely, submit scans, query scan statuses, retrieve reports etc.

### Executing the scripts

Every .py script automates specific task and expects at least the ScanSuite server URL, username and password to be provided.

Password can be provided inline with `-p` or entered at the password prompt. Using
the prompt avoids storing the password in shell history.

The Git scanning tool accepts scanner selection and repository scanning mode from
the command line. Some older scripts still define their scanner selection in the
script.

Execute `python scansuite-scan-...py -h` for each script to list all accepted parameters and expected values.

### Static code analysis

Provide the code archive in ZIP format:

```bash
python scansuite-scan-zip.py \
  -s "https://my-scansuite-server.com" \
  -u user \
  -l java \
  -f /path/to/test.zip \
  --engagement-id local-0123456789ac
```

Run a Custom Scope scan against selected files in the archive:

```bash
python scansuite-scan-zip.py \
  -s "https://my-scansuite-server.com" \
  -u user \
  -l java \
  -f /path/to/test.zip \
  --engagement-id local-0123456789ab \
  --mode custom-scope \
  --scope src/main/java/ \
  --scope pom.xml \
  --scope '**/*Controller.java' \
  --scanners mlsast,sast_quick
```

The ZIP tool supports the same `--scope-file`, `--scanners`, MLSAST reachability
and architecture switches, `--repository-url`, `--product-name`, and
`--engagement-id` controls as the Git tool. Git-history analysis is disabled for
archives by default and can be enabled with `--mlsast-git-history` when the
archive contains Git metadata. Custom Scope retains the complete extracted
archive for MLSAST reachability and architecture analysis while scanning only
matched files.

Incremental Scan and Monitor Changes are intentionally unavailable for ZIP
archives because an archive has no remote commit identity or verifiable prior
Git revision. Use `scansuite-scan-git.py --mode incremental` or
`--mode monitor-changes` for those workflows.

Scan a Git repository once with the default scanners (`mlsast,secrets`):

```bash
python scansuite-scan-git.py -s "https://my-scansuite-server.com" -u user -l python -g "https://github.com/NetSPI/django.nV" -r "https://github.com/NetSPI/django.nV" -b main
```

Omit `--branch-name` to scan the repository's default branch. The secrets finding
links use `--repository-url`, which defaults to `--giturl`. Specify it explicitly
when the clone URL is different from the browsable repository URL, such as when
using SSH to clone.

#### Git scanning modes

Run a one-time incremental scan. The server compares the current revision with
the latest compatible successful repository scan. The first incremental run is a
full scan. Reuse the same engagement ID, repository URL, scanner configuration,
branch, and language on later runs so the server can find the compatible
checkpoint:

```bash
python scansuite-scan-git.py \
  -s "https://my-scansuite-server.com" \
  -u user \
  -l java \
  -g "https://github.com/cepxeo/vulnado" \
  --engagement-id local-0123456789ab \
  -b main \
  --mode incremental
```

When `--engagement-id` is omitted, the tool creates a product using the
repository name, or the value supplied through `--product-name`. It prints the
resolved engagement ID; save and reuse that value for subsequent incremental
scans. If the product already exists, provide its engagement ID instead of
trying to create it again.

A successful standard `--mode once` Git scan also creates this checkpoint. You
can therefore run a normal full scan first and later switch to `--mode
incremental` or create `--mode monitor-changes`; only commits after the compatible
full scan are included. Custom Scope and ZIP scans are not used as Git
checkpoints.

Run a one-time Custom Scope scan with patterns supplied on the command line.
Quote glob patterns so the local shell does not expand them:

```bash
python scansuite-scan-git.py \
  -s "https://my-scansuite-server.com" \
  -u user \
  -l java \
  -g "https://github.com/cepxeo/vulnado" \
  --engagement-id local-0123456789ab \
  --mode custom-scope \
  --scope src/main/java/ \
  --scope pom.xml \
  --scope '**/*Controller.java'
```

Custom Scope can also read one pattern per line from a UTF-8 file:

```text
src/main/java/
pom.xml
**/*Controller.java
```

```bash
python scansuite-scan-git.py \
  -s "https://my-scansuite-server.com" \
  -u user \
  -l java \
  -g "https://github.com/cepxeo/vulnado" \
  --engagement-id local-0123456789ab \
  --mode custom-scope \
  --scope-file ./scan-scope.txt
```

Patterns are resolved by the server against tracked files in the selected Git
revision. Only the resolved files are scanned, while the complete ephemeral
checkout remains available for optional MLSAST reachability and architecture
analysis. An empty or unsafe scope fails instead of falling back to a full scan.

Create a Monitor Changes definition. It runs immediately and is subsequently
checked by the server's repository monitor:

```bash
python scansuite-scan-git.py \
  -s "https://my-scansuite-server.com" \
  -u user \
  -l multilanguage \
  -g "git@github.com:example/application.git" \
  -r "https://github.com/example/application" \
  --engagement-id local-0123456789ab \
  --mode monitor-changes \
  --scan-name application-monitor
```

The other accepted values for `--mode` are `once`, `daily`, `weekly`, and
`monthly`. Scheduled and Monitor Changes modes use `--scan-name` as the saved
definition name. Incremental and Custom Scope are always one-time operations.

#### Scanner configurations

Select scanners with a comma-separated list:

```bash
# Native scanners without MLSAST
python scansuite-scan-git.py ... --scanners sast_quick,iacs_kics

# MLSAST with reachability, but without Git-history or architecture processing
python scansuite-scan-git.py ... \
  --scanners mlsast \
  --no-mlsast-git-history \
  --no-security-architecture

# MLSAST without reachability verification
python scansuite-scan-git.py ... --scanners mlsast --no-reachability
```

Available scanner IDs are `mlsast`, `sast_quick`, `sast_full`, `sast_custom`,
`secrets`, `snyk`, `dep_checks`, `iacs_kics`, `gen_docs`, and `code_flow`.
Custom Scope supports only `mlsast`, `sast_quick`, `sast_full`, `sast_custom`,
and `iacs_kics`; the CLI validates this before submitting the scan. Its default
scanner is therefore `mlsast`, while other modes default to `mlsast,secrets`.

### Dynamic web scan

```
python scansuite-scan-web.py -s "https://my-scansuite-server.com" -u user -w "https://scanthisserver.com, https://anotherserver.edu"

```

### Infrastructure scan

```
python scansuite-scan-infra.py -s "https://my-scansuite-server.com" -u admin -t "192.168.23.3, 192.168.24.0/24" --ping "No" --ports "All TCP" --scan_type "vulnerability_scan" --product_name "DMZ Scan January"
```

### Dumping BitBucket repositories

Script serves specific usecase when local BitBucket server is in use, containing projects with code repositories.

* Specify local BitBucket server name in the script.
* Obtain the HTTP key/token from the BitBucket user profile.
* Submit it to the script along with the comma separated list of project names and, optionally, specific repositories.

The script will download required repositories from the given project and make and archive from them, suitable to upload to ScanSuite for further static code analysis.

BitBucket token can be provided either inline with `--token` parameter or entered via promped field, same as other mandatory fields.

This will clone and ZIP all repos from given projects:

```
python bitbucket-clone-projects-repos.py --token YOUR_TOKEN --projects PROJONE,PROJTWO
```

This will clone and ZIP specified repos from given projects:

```
python bitbucket-clone-projects-repos.py --token YOUR_TOKEN --projects PROJONE --repos mycode-repository,another-repository,
```

