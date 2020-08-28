#!/bin/sh

set -e 

PROJECT_NAME=$(basename "${PWD}")
PROJECT_VERSION=${1}
RELEASE_DIR="${PWD}/release"

if [ -z "${1}" ]; then
    # we take the last "tag" of the Git repository as version
    PROJECT_VERSION=$(git describe --abbrev=0 --tags)
    echo Version: "${PROJECT_VERSION}"
fi

mkdir -p "${RELEASE_DIR}"
if [ -f "${RELEASE_DIR}/${PROJECT_NAME}-${PROJECT_VERSION}_composer.tar.xz" ]; then
    echo "Version ${PROJECT_VERSION} already has a release!"
    exit 1
fi

git archive --prefix "${PROJECT_NAME}-${PROJECT_VERSION}/" "${PROJECT_VERSION}" -o "${RELEASE_DIR}/${PROJECT_NAME}-${PROJECT_VERSION}_composer.tar.xz"
(
    cd "${RELEASE_DIR}"
    tar -xJf "${PROJECT_NAME}-${PROJECT_VERSION}_composer.tar.xz"
    (
    	cd "${PROJECT_NAME}-${PROJECT_VERSION}"
       	composer update --optimize-autoloader --no-dev
    )
    tar -cJf "${PROJECT_NAME}-${PROJECT_VERSION}_composer.tar.xz" "${PROJECT_NAME}-${PROJECT_VERSION}"
    rm -rf "${PROJECT_NAME}-${PROJECT_VERSION}"
)
gpg2 --armor --detach-sign "${RELEASE_DIR}/${PROJECT_NAME}-${PROJECT_VERSION}_composer.tar.xz"
minisign -Sm "${RELEASE_DIR}/${PROJECT_NAME}-${PROJECT_VERSION}_composer.tar.xz"
