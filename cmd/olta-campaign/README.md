# Olta Campaign

`olta-campaign` is Olta's campaign administration and delivery service. Its entry point lives in this directory; reusable campaign logic, database models, templates, and static assets live under `pkg/campaign`.

Olta requires Go 1.22 or newer. Build from the repository root:

```sh
go build -o build/olta-campaign ./cmd/olta-campaign
```

Run from the repository root or the command directory. Runtime asset discovery checks both layouts:

```sh
./build/olta-campaign -config cmd/olta-campaign/config.json
```

On first start, SQLite and MySQL databases are initialized from the embedded unified Olta schema. The service does not require a migration directory beside the binary.

Olta Campaign preserves the Gophish campaign model and UI foundations. See the repository root README and license files for usage, attribution, and licensing details.
