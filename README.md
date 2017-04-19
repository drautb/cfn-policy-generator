CloudFormation Policy Generator
===============================

Attempts to generate the least-privileged IAM policy required to deploy
an AWS CloudFormation template.

It doesn't do any magic, nor does it make any AWS calls. It simply consults
a catalog of the needed permissions for each CloudFormation resource type.
The needed permissions can vary depending on which fields are populated on
the resource.

A very small number of resources are supported right now. I'll be adding
more over time, but pull requests are also welcome.

### Example

For JSON templates:

```
curl -H "Content-Type: application/json" --data @template.json https://cfn-policy-generator.herokuapp.com/cloudformation/2010-09-09/template
```

For YAML templates:

```
curl -H "Content-Type: application/x-yaml" --data @template.yml https://cfn-policy-generator.herokuapp.com/cloudformation/2010-09-09/template
```

### Local Testing

Run `racket server.rkt`.
