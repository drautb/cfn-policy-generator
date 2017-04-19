#lang racket

(require json
         racket/runtime-path)

(module+ test
  (require rackunit
           rackunit/text-ui))

;; generate-policy is the public API
(provide generate-policy)

;; Load JSON data
(define-runtime-path rules-path "data/rules/2010-09-09")
(define-runtime-path resource-formats-path "data/resource-formats.json")

(define RULES
  ((λ ()
     (log-info "Loading rules from path. path=~a" rules-path)
     (for/hash ([path (in-directory rules-path)])
       (log-info "Loading rules for resource. file=~a" path)
       (values (path->string (path-replace-extension (file-name-from-path path) ""))
               (with-input-from-file path (λ () (read-json))))))))

(define RESOURCE-FORMATS
  ((λ ()
     (log-info "Loading resource formats. file=~a" resource-formats-path)
     (with-input-from-file resource-formats-path
       (λ () (read-json))))))

;; hash-ref* : hash? symbol? -> any
;; Helper hash-ref to check both the symbol and string version of the key.
(define (hash-ref* data key)
  (hash-ref data key (λ () (hash-ref data (symbol->string key)))))

(module+ test
  (define-test-suite test-hash-ref*
    (test-case "hash-ref* should find a hash value by symbol or string"
      (check-equal? (hash-ref* (hash "key" "value") 'key) "value")))

  (run-tests test-hash-ref*))

;; structs
;; Used to make sorting/deduping actions a bit easier.
(struct action (service-name action-name) #:transparent)
(struct action-group (service-name action-list) #:transparent)

(define (make-action str)
  (let ([pieces (string-split str ":")])
    (action (first pieces) (second pieces))))

(module+ test
  (define-test-suite test-make-action
    (test-case "make-action should work"
      (check-equal? (make-action "ec2:LaunchInstance")
                    (action "ec2" "LaunchInstance"))))

  (run-tests test-make-action))

;; make-policy - (listof hash) -> hash
;; wraps a list of stateents in a hash that represents a policy document.
(define (make-policy statements)
  (hash 'Version "2012-10-17"
        'Statement statements))

;; make-statement - (listof string) -> hash
;; wraps a list of action strings in a hash that represents a policy statement.
(define (make-statement actions resource)
  (hash 'Effect "Allow"
        'Action actions
        'Resource resource))

;; get-resources - hash -> hash
;; Given a template, this extracts the resources hash from the template if one exists,
;; otherwise it returns an empty hash.
(define (get-resources template)
  (if (hash-has-key? template 'Resources)
      (hash-ref* template 'Resources)
      (begin
        (log-info "Template doesn't have a 'Resources' key.")
        (hash))))

;; get-actions : hash hash -> (listof action)
;; Takes a hash representing the rule, and and the resource definition, and returns a list of actions.
;; Called recursively on subsets of the rule and resource for additional permissions.
(define (get-actions rule resource-def)
  (append (if (hash-has-key? rule 'core)
              (map make-action (hash-ref* rule 'core))
              empty)
          (if (hash-has-key? rule 'extended)
              (if (hash? resource-def)
                  (hash-map resource-def
                            (λ (resource-key resource-def)
                              (define extended-rule (hash-ref* rule 'extended))
                              (if (hash-has-key? extended-rule resource-key)
                                  (get-actions (hash-ref* extended-rule resource-key)
                                               resource-def)
                                  empty)))
                  (map (λ (def)
                         (get-actions rule def))
                       resource-def))
              empty)))

;; get-all-actions : hash hash -> (listof action)
;; Returns a list of _all_ actions needed by the tempate based on the given rules.
(define (get-all-actions rules resources)
  (remove-duplicates
   (flatten
    (hash-map resources
              (λ (resource-name resource-def)
                (define resource-type
                  (let ([raw-type (hash-ref* resource-def 'Type)])
                    (if (string-prefix? raw-type "Custom::")
                        "AWS-CloudFormation-CustomResource"
                        (string-replace raw-type "::" "-"))))
                (if (hash-has-key? rules resource-type)
                    (remove-duplicates
                     (get-actions (hash-ref* rules resource-type)
                                  resource-def))

                    (begin
                      (log-warning "No rules found for resource type! resource=~a" resource-type)
                      empty)))))))

;; consolidate--actions : (listof action) -> (listof action-group)
;; Collapses a single mixed list of actions into a list of action-groups,
;; each containing actions that pertain to a single service.
(define (consolidate-actions action-list)
  (define service-names
    (remove-duplicates
     (map (λ (action)
            (action-service-name action))
          action-list)))
  (for/list ([s service-names])
    (action-group s (sort (map (λ (action)
                                 (string-append (action-service-name action) ":"
                                                (action-action-name action)))
                               (filter (λ (action)
                                         (equal? (action-service-name action) s))
                                       action-list))
                          string<?))))

(module+ test
  (check-equal? (consolidate-actions (list (action "ec2" "one")
                                           (action "ec2" "two")
                                           (action "s3" "three")))
                (list (action-group "ec2" (list "ec2:one" "ec2:two"))
                      (action-group "s3" (list "s3:three")))))

;; build-policy : hash hash -> hash
;; takes a hash representing a CFN template, returns a hash representing a policy.
(define (build-policy rules resource-formats template)
  (define resources (get-resources template))
  (define action-list (get-all-actions rules resources))
  (define action-groups (consolidate-actions action-list))
  (make-policy
   (map (λ (action-group)
          (make-statement (action-group-action-list action-group)
                          (hash-ref* resource-formats
                                     (string->symbol
                                      (action-group-service-name action-group)))))
        action-groups)))

(module+ test
  (define EMPTY-POLICY (make-policy empty))

  (define TEST-RULES
    (hash "AWS-Service-ResourceName"
          (hash 'core
                (list "prefix:permission2"
                      "prefix:permission1")
                'extended
                (hash 'Properties
                      (hash 'core
                            (list "prefix:permission3")
                            'extended
                            (hash 'SomeServiceProperty
                                  (hash 'core
                                        (list "prefix:permission5"
                                              "prefix:permission4"))))))
          "AWS-Service-OtherResourceName"
          (hash 'core
                (list "other:other1"
                      "other:other2"))
          "AWS-Service-ListResource"
          (hash 'core
                (list "list:list1"
                      "list:list2")
                'extended
                (hash 'Properties
                      (hash 'extended
                            (hash 'Name
                                  (hash 'core
                                        (list "list:list3"))
                                  'Something
                                  (hash 'core
                                        (list "list:list4"))))))

          "AWS-Service-EmptyResource"
          (hash)

          "AWS-CloudFormation-CustomResource"
          (hash 'core (list "custom:custom1"))))

  (define TEST-RESOURCE-FORMATS
    (hash 'prefix "prefix-resource"
          'other "other-resource"
          'list "list-resource"
          'custom "*"))

  (define (run-test template expected-policy)
    (check-equal? (build-policy TEST-RULES TEST-RESOURCE-FORMATS template)
                  expected-policy))

  (define-test-suite test-policy-generation

    (test-case "Should build an empty policy if there are no resources in the template"
      (run-test (hash) EMPTY-POLICY))

    (test-case "Should build an empty policy if the resource type isn't recognized"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "bogus")))
                EMPTY-POLICY))

    (test-case "Should build an empty policy if the resource has no core rules"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "AWS::Service::EmptyResource")))
                EMPTY-POLICY))

    (test-case "Should build a policy with the core permissions"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "AWS::Service::ResourceName")))
                (make-policy
                 (list (make-statement (list "prefix:permission1"
                                             "prefix:permission2")
                                       "prefix-resource")))))

    (test-case "Should build a policy with extra core permissions from an extended level"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "AWS::Service::ResourceName"
                                  'Properties (hash))))
                (make-policy
                 (list (make-statement (list "prefix:permission1"
                                             "prefix:permission2"
                                             "prefix:permission3")
                                       "prefix-resource")))))

    (test-case "Should build a policy with multiple levels of extended permissions"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "AWS::Service::ResourceName"
                                  'Properties (hash 'SomeServiceProperty (hash)))))
                (make-policy
                 (list (make-statement (list "prefix:permission1"
                                             "prefix:permission2"
                                             "prefix:permission3"
                                             "prefix:permission4"
                                             "prefix:permission5")
                                       "prefix-resource")))))

    (test-case "Should build a policy with multiple statements for multiple resources"
      (run-test (hash 'Resources
                      (hash "firstResource"
                            (hash 'Type "AWS::Service::ResourceName")
                            "secondResource"
                            (hash 'Type "AWS::Service::OtherResourceName")))
                (make-policy
                 (list (make-statement (list "prefix:permission1"
                                             "prefix:permission2")
                                       "prefix-resource")
                       (make-statement (list "other:other1"
                                             "other:other2")
                                       "other-resource")))))

    (test-case "Should build a policy correctly for resources that contain lists of items"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "AWS::Service::ListResource"
                                  'Properties (list (hash 'Name "")
                                                    (hash 'Something "")))))
                (make-policy
                 (list (make-statement (list "list:list1"
                                             "list:list2"
                                             "list:list3"
                                             "list:list4")
                                       "list-resource")))))

    (test-case "Should not duplicate actions within a list"
      (run-test (hash 'Resources
                      (hash "resourceName"
                            (hash 'Type "AWS::Service::ListResource"
                                  'Properties (list (hash 'Name "")
                                                    (hash 'Name "")))))
                (make-policy
                 (list (make-statement (list "list:list1"
                                             "list:list2"
                                             "list:list3")
                                       "list-resource")))))

    (test-case "Should not duplicate statements within a list"
      (run-test (hash 'Resources
                      (hash "first"
                            (hash 'Type "AWS::Service::ResourceName")
                            "second"
                            (hash 'Type "AWS::Service::ResourceName")))
                (make-policy
                 (list (make-statement (list "prefix:permission1"
                                             "prefix:permission2")
                                       "prefix-resource")))))

    (test-case "Should consolidate permissions for the same service into a single statement"
      (run-test (hash 'Resources
                      (hash "first"
                            (hash 'Type "AWS::Service::ResourceName")
                            "second"
                            (hash 'Type "AWS::Service::ResourceName"
                                  'Properties (hash))))
                (make-policy
                 (list (make-statement (list "prefix:permission1"
                                             "prefix:permission2"
                                             "prefix:permission3")
                                       "prefix-resource")))))
    (test-case "Should use the CFN custom resource rules for resources that start with 'Custom::'"
      (run-test (hash 'Resources
                      (hash "first"
                            (hash 'Type "Custom::myResource")))
                (make-policy
                 (list (make-statement (list "custom:custom1")
                                       "*"))))))

  (run-tests test-policy-generation))


(define (generate-policy template-hash)
  (build-policy RULES RESOURCE-FORMATS template-hash))
