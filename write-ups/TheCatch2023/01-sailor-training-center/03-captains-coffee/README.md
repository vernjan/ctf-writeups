# Ship web server

Ahoy, deck cadet,

there are rumors that on the ship web server is not just the official presentation. Your task is to disprove or confirm these rumors.

May you have fair winds and following seas!

Ship web server is available at http://www.cns-jv.tcc.

---

Visiting the page tell us
```
{"status":"Coffemaker ready","msg":"Visit /docs for documentation"}
```

http://coffee-maker.cns-jv.tcc/docs hosts an OpenApi docs. There are 2 methods:
- `GET /coffeeMenu`
- `POST /makeCoffee`

Calling `coffeeMenu`:
```json
{
  "Menu": [
    {
      "drink_name": "Espresso",
      "drink_id": 456597044
    },
    {
      "drink_name": "Lungo",
      "drink_id": 354005463
    },
    {
      "drink_name": "Capuccino",
      "drink_id": 234357596
    },
    {
      "drink_name": "Naval Espresso with rum",
      "drink_id": 501176144
    }
  ]}
```

Let's try `/makeCoffee` with `{ "drink_id": 501176144 }`:

```
{
  "message": "Your Naval Espresso with rum is ready for pickup",
  "validation_code": "Use this validation code FLAG{ccLH-dsaz-4kFA-P7GC}"
}
```
