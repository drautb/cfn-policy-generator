#lang racket

(require json
         racket/runtime-path)

(provide generate-policy)

(define-runtime-path rules-path "rules/2010-09-09")

(define (load-rules)
  (log-info "Loading rules from path. path=~a" rules-path)
  (for/hash ([path (in-directory rules-path)])
    (log-info "Loading rules for resource. file=~a" path)
    (values (path->string (path-replace-extension (file-name-from-path path) ""))
            (with-input-from-file path (λ () (read-json))))))

(define RULES (load-rules))

;; get-actions : hash hash -> hash
;; Takes a hash representing the rule, and and the resource definition, and returns a list of actions.
;; Called recursively on subsets of the rule and resource for additional permissions.
(define (get-actions rule resource-def)
  (flatten
   (append (if (hash-has-key? rule 'core)
               (hash-ref rule 'core)
               empty)
           (if (hash-has-key? rule 'extended)
               (if (hash? resource-def)
                   (hash-map resource-def
                             (λ (resource-key resource-def)
                               (define extended-rule (hash-ref rule 'extended))
                               (if (hash-has-key? extended-rule resource-key)
                                   (flatten (get-actions (hash-ref extended-rule resource-key)
                                                         resource-def))
                                   empty)))
                   (flatten (map (λ (def)
                                   (get-actions rule def))
                                 resource-def)))
               empty))))

;; build-policy : hash hash -> hash
;; takes a hash representing a CFN template, returns a hash representing a policy.
(define (build-policy rules template)
  (define resources
    (if (hash-has-key? template 'Resources)
        (hash-ref template 'Resources)
        (begin
          (log-info "Template doesn't have a 'Resources' key.")
          (hash))))
  (hash 'Version "2012-10-17"
        'Statement
        (remove-duplicates
         (flatten
          (hash-map resources
                    (λ (resource-name resource-def)
                      (define resource-type
                        (string-replace (hash-ref resource-def 'Type) "::" "-"))
                      (if (hash-has-key? rules resource-type)
                          (let ([actions (remove-duplicates
                                          (get-actions (hash-ref rules resource-type)
                                                       resource-def))])
                            (if (empty? actions) actions
                                (hash 'Effect "Allow"
                                      'Action actions
                                      'Resource "*")))
                          (begin
                            (log-warning "No rules found for resource type! resource=~a" resource-type)
                            empty))))))))

(module+ test
  (require rackunit)

  (define (wrap-statements stmts)
    (hash 'Version "2012-10-17"
          'Statement stmts))

  (define (wrap-permissions actions)
    (hash 'Effect "Allow"
          'Action actions
          'Resource "*"))

  (define EMPTY-POLICY (wrap-statements empty))

  (define TEST-RULES
    (hash "AWS-Service-ResourceName"
          (hash 'core
                (list "prefix:permission1"
                      "prefix:permission2")
                'extended
                (hash 'Properties
                      (hash 'core
                            (list "prefix:permission3")
                            'extended
                            (hash 'SomeServiceProperty
                                  (hash 'core
                                        (list "prefix:permission4"
                                              "prefix:permission5"))))))
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
          (hash)))

  ;; Should build an empty policy if there are no resources in the template.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash))
                EMPTY-POLICY)

  ;; Should build an empty policy if the resource type isn't recognized.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "bogus"))))
                EMPTY-POLICY)

  ;; Should build an empty policy if the resource has no core rules.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "AWS::Service::EmptyResource"))))
                EMPTY-POLICY)

  ;; Should build a policy with the core permissions.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "AWS::Service::ResourceName"))))
                (wrap-statements
                 (list (wrap-permissions (list "prefix:permission1"
                                               "prefix:permission2")))))


  ;; Should build a policy with extra core permissions from an extended level
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "AWS::Service::ResourceName"
                                   'Properties (hash)))))
                (wrap-statements
                 (list (wrap-permissions (list "prefix:permission1"
                                               "prefix:permission2"
                                               "prefix:permission3")))))

  ;; Should build a policy with multiple levels of extended permissions.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "AWS::Service::ResourceName"
                                   'Properties (hash 'SomeServiceProperty (hash))))))
                (wrap-statements
                 (list (wrap-permissions (list "prefix:permission1"
                                               "prefix:permission2"
                                               "prefix:permission3"
                                               "prefix:permission4"
                                               "prefix:permission5")))))

  ;; Should build a policy with multiple statements for multiple resources.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "firstResource"
                             (hash 'Type "AWS::Service::ResourceName")
                             "secondResource"
                             (hash 'Type "AWS::Service::OtherResourceName"))))
                (wrap-statements
                 (list (wrap-permissions (list "prefix:permission1"
                                               "prefix:permission2"))
                       (wrap-permissions (list "other:other1"
                                               "other:other2")))))

  ;; Should build a policy correctly for resources that contain lists of items.
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "AWS::Service::ListResource"
                                   'Properties (list (hash 'Name "")
                                                     (hash 'Something ""))))))
                (wrap-statements
                 (list (wrap-permissions (list "list:list1"
                                               "list:list2"
                                               "list:list3"
                                               "list:list4")))))

  ;; Should not duplicate actions within a list
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "resourceName"
                             (hash 'Type "AWS::Service::ListResource"
                                   'Properties (list (hash 'Name "")
                                                     (hash 'Name ""))))))
                (wrap-statements
                 (list (wrap-permissions (list "list:list1"
                                               "list:list2"
                                               "list:list3")))))

  ;; Should not duplicate statements within a list
  (check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "first"
                             (hash 'Type "AWS::Service::ResourceName")
                             "second"
                             (hash 'Type "AWS::Service::ResourceName"))))
                (wrap-statements
                 (list (wrap-permissions (list "prefix:permission1"
                                               "prefix:permission2")))))

  ;; Should consolidate permissions for the same service into a single statement
  #;(check-equal? (build-policy
                 TEST-RULES
                 (hash 'Resources
                       (hash "first"
                             (hash 'Type "AWS::Service::ResourceName")
                             "second"
                             (hash 'Type "AWS::Service::ResourceName"
                                   'Properties (hash)))))
                (wrap-statements
                 (list (wrap-permissions (list "prefix:permission1"
                                               "prefix:permission2"
                                               "prefix:permission3")))))

  )


(define (generate-policy template-hash)
  (log-info "Generating policy for template.")
  (build-policy RULES template-hash))
