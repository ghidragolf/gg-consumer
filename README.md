## Consumer
[Consumer.py](./app/consumer.py) (referred to as gg-consumer) is the back end application of [Ghidra Golf](https://ghidra.golf) that ingests a user submitted Ghidra Script from RabbitMQ to execute against a given challenge binary (cb). Ghidra's analyzeHeadless script is used for headlessly running Ghidra Scripts against a given cb. The following Python dataclass is populated via a competitors submission object obtained from RabbitMQ by the [ctfd-fileupload](https://github.com/ghidragolf/ctfd-fileupload) plugin.

```bash
@dataclass
class GGStruct:
    '''
    Class to store RabbitMQ GStruct. These parameters populate and are passed to Ghidra Runners.
    '''
    sub_id: str = None # submission value (UUID)
    user_id: str = None      # User id from CTFd
    challenge: str = None    # Name of the challenge
    challenge_id: int = None # ID for challenge
    filename: str = None     # name of uploaded file
    content: str = None      # uploaded content
```

For a complete view of the competition infrastructure see [ctfd-ghidragolf](https://github.com/ghidragolf/ctfd-ghidragolf).

## Contributing
Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for contributing to this project.

## Envrionment Setup
The [Dockerfile](./Dockerfile) creates the required directories (```/analysis```, ```/binaries```, ```/core-scritps```, ```/glogdir```) within the Docker container for the  Ghidra Golf consumer and installs necessary dependencies. The Dockerfile pulls Ghidra 10.2.2, but this can be updated to fit the competition architects needs. The recommended deployment option is with docker-compose to handle mounting folders from the host to the container. See [ctfd-ghidragolf](https://github.com/ghidragolf/ctfd-ghidragolf) for a reference. If running the gg-consumer container stand-alone, ensure folders from the host machine are mounted within the container via the ```-v``` flag.

Build the docker container via:

``` bash
$> docker build . -t gg:consumer
```

If installing outside of a Docker container, ensure python3-dev(Debian based)/python3-devel(RHEL based) packages are installed to avoid errors.
On RHEL based systems, this is accomplished via:
* ```sudo dnf install python3-devel```

On Debian based systems, this is accomplished via:
* ```sudo apt-get install python3-dev```

## Configuration
[consumer.py](./consumer.py) is configured by default to only consume one event at a time from a RabbitMQ queue.
This enables the end-user to spawn N-number of consumer containers in a competition environment with each container consuming and analyzing one binary with Ghidra's [analyzeHeadless](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/Linux/support/analyzeHeadless) at a time. It is recommended to run multiple consumers to fit your competition needs.

[Consumer.py](./consumer.py) expects the following directory structure at the root directory (/) of the container.
* ```/binaries```: binaries to run Ghidra scripts against. CTFd challenge names **MUST** match the binary names.
    * ex: Challenge helloworld in CTFd needs a binary called helloworld in ```/binaries```.
* ```/submissions```:user submitted Ghidra script stored in ```submissions/<team_name>/<submission_id>```. 
* ```/glogdir```:log file Ghidra's ```analyzeHeadless``` writes data to,  which is later ingested and POSTed to the custom [CTFd API endpoint](https://github.com/ghidragolf/ctfd-fileupload).

### Defensive Measures for Ghidra Golf Consumer
gg-consumer fundamentally builds and executes an ```analyzeHeadless```one-liner via user supplied parameters.
This presents an opportunity for command injection. In order to prevent rogue competitors from abusing this critical functionality of the competition the following defensive measures were leveraged at ShmooCon. By no means is this an exhaustive list of defensive measures.

0. Competition Policy explicitly stating the banning of a team caught attacking/abusing competition infrastructure.
1. Data Sanitization of the submitted GGStruct object.
2. YARA scanning of the Ghidra Script itself is optional for the competition architects.
   * If a YARA rule is flagged, the competitor is alerted along with their submission ID to be investigated by competition architects in the event a false positive occurred.
3. The gg-consumer Docker container runs as a non-root user.
4. The gg-consumer Docker container runs with all [capabilities](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) dropped to prevent post-execution abuse.
5. Vulnerability scanning of containers.
6. All gg-consumer containers running during the first Ghidra Golf event at ShmooCon  were executed on a docker network without internet access.
7. All gg-consumer containers were running on a non-internet connected machine that was directly connected to the CTFd/RabbitMQ infrastructure.
8. Timeout of analyzeHeadless execution of two minutes.

For more tips, leverage [OWASP Container Security cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html).


## Tests
* Running tests:
``` bash
$> python3 -m unittest tests/submissionTests.py
```

## Running
* When running consumer.py outside of a Docker container, analyzeHeadless must be in the user's path, and the directory structure described above must be created.

```bash
$> python3 consumer.py --rabbitmqhost rabbitmq --rabbitmqqueue GhidraGolf --ctfd ctfd_host
```

* with Docker:
```bash
$> docker run gg:consumer
```

See [ctfd-ghidragolf](https://github.com/ghidragolf/ctfd-ghidragolf) for an out-of-the-box test configuration.

## Augmenting with a Different RE Tool
Competitors of Ghidra Golf expressed interest in leveraging this infrastructure for other RE tools.
Simply modify the Docker container to have a tool of your choice in addition to modifying the [```ghidraRun```](https://github.com/ghidragolf/gg-consumer/blob/dev/app/GhidraGolf.py#L167)
function within [```GhidraGolf.py```](./app/GhidraGolf.py) to achieve execution of user supplied scripts of a given cb.
