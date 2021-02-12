![](https://www.metsys.fr/wp-content/themes/metsys/images/svg/metsys-logo.svg "Metsys")
# Hunting Rules
## HuntingRule01
### Hunt Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://medium.com/falconforce/falconfriday-detecting-certutil-and-suspicious-code-compilation-0xff02-cfe8fb5e159e?source=friends_link&sk=3c63b684a2f6a203d8627554cec9a628)

### ATT&CK Tags

> Tactics: [u'Persistence', u'LateralMovement', u'Collection']

### Hunt details

> Description: test

> Query:

```t
```SecurityEvent | where EventID == "4687" | where CommandLine contains "-noni -ep bypass $"
```

## HuntingRule02
### Hunt Tags

> Author: [thomas couilleaux](https://www.metsys.fr/)

> Reference: [Link to medium post](https://medium.com/falconforce/falconfriday-detecting-certutil-and-suspicious-code-compilation-0xff02-cfe8fb5e159e?source=friends_link&sk=3c63b684a2f6a203d8627554cec9a628)

### ATT&CK Tags

> Tactics: [u'Persistence', u'LateralMovement']

### Hunt details

> Description: test

> Query:

```t
```SecurityEvent | where EventID == "4688" | where CommandLine contains "-noni -ep bypass $"
```

