FROM debian:stable-slim

RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      bash curl ca-certificates python3 coreutils gawk \
 && apt-get clean

COPY age_funcs.sh driver.sh pkgs.tsv /harness/
RUN chmod +x /harness/driver.sh

# Deliberately absent: the gh CLI, GH_TOKEN/GITHUB_TOKEN, and any warm cache.
# The cold anonymous run is the case the fix has to survive.
ENTRYPOINT ["/bin/bash", "/harness/driver.sh"]
