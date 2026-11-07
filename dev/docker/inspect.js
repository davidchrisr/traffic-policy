// Read-only views of the controller database for inspect.sh, which validates the view name.
const { Database } = require("bun:sqlite");

const queries = {
  status: `SELECT json_extract(desired, '$.revision') AS desired,
      json_extract(applied, '$.revision') AS applied, last_error AS lastError,
      (SELECT group_concat(code) FROM conditions WHERE recovered_at IS NULL) AS activeConditions
    FROM policy`,
  conditions: `SELECT code, occurrences, first_at AS firstAt, recovered_at AS recoveredAt, message
    FROM conditions ORDER BY first_at`,
  instances: `SELECT json(value) AS instance
    FROM policy, json_each(json_extract(desired, '$.instances'))`,
  requests: `SELECT client_ip AS clientIp, attempts, last_at AS lastAt, dismissed_at AS dismissedAt
    FROM host_requests ORDER BY last_at`,
};

const database = new Database(
  "/var/lib/traffic-policy/controller/controller.sqlite3",
  { readonly: true },
);

for (const row of database.query(queries[process.argv[2]]).all())
  console.log(
    JSON.stringify(row.instance === undefined ? row : JSON.parse(row.instance)),
  );
