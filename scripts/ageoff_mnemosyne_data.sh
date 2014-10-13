#!/bin/bash

set -e

DATE=$(date -d '30 days ago' +%FT00:00:00.000Z)

echo "[`date`] Deleting session and hpfeeds data older than $DATE..."

for COLLECTION in session hpfeed;
do
    REMOVE_CMD="db.${COLLECTION}.remove( { timestamp: {\$lt: ISODate(\"${DATE}\") }  } )"
    /usr/bin/mongo mnemosyne --eval "$REMOVE_CMD"
done

echo "[`date`] done"
