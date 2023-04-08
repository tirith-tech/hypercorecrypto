# hypercorecrypto

Golang implementation of [hypercore-crypto](https://github.com/mafintosh/hypercore-crypto).

These are the crypto primitives used in hypercore, extracted into a separate module

```
import "github.com/tirith-tech/hypercorecrypto"
```

## Usage

``` golang
import (
	"fmt"

	crypto "github.com/tirith-tech/hypercorecrypto"
)

keyPair := crypto.NewKeyPair()
fmt.Println("Generated key pair:", keyPair)

```

## API

#### `keyPair := crypto.NewKeyPair()`

Returns an `ED25519` keypair that can used for tree signing.

#### `signature := crypto.Sign(message, secretKey)`

Signs a message (buffer).

#### `verified := crypto.Verify(message, signature, publicKey)`

Verifies a signature for a message.

#### `hash := crypto.Data(data)`

Hashes a leaf node in a merkle tree.

#### `hash := crypto.Parent(a, b)`

Hash a parent node in a merkle tree. `a` and `b` should look like this:

```golang
type TreeNode struct {
    Index uint64
    Hash  []byte
    Size  uint64
}
```

#### `hash := crypto.Tree(peaks)`

Hashes the merkle root of the tree. `peaks` should be an array of the peaks of the tree and should be of type `TreeNode` like above.

#### `buffer := crypto.RandomBytes(size)`

Returns a buffer containing random bytes of size `size`.

#### `hash := crypto.DiscoveryKey(publicKey)`

Return a hash derived from a `publicKey` that can used for discovery
without disclosing the public key.

#### `list := crypto.Namespace(name, count)`

Make a list of namespaces from a specific publicly known name.
Use this to namespace capabilities or hashes / signatures across algorithms.

## License

MIT