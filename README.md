# Intro

Tool for discovery sensitive objects in code


# Install

pip3 install semgrep-discovery


# Run

```
semgrep-discovery --wd ./django-realworld-example-app/ --langs python --objects dtos --keywords email,password --outfile ./result.json --format json
Starting scan....
     workdir: /home/kali/django-realworld-example-app
     langs: ['python']
     objects: ['dtos']
     keywords: ['email', 'password']
     ruledir: /home/kali/.local/lib/python3.11/site-packages/semgrep_discovery/rules
Add rule /home/kali/.local/lib/python3.11/site-packages/semgrep_discovery/rules/python/dtos.yaml for scan
Run scan /home/kali/django-realworld-example-app with rule /home/kali/.local/lib/python3.11/site-packages/semgrep_discovery/rules/python/dtos.yaml
    [ lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object ]
        Article
            fields:    ['slug', 'title', 'description', 'body', 'author', 'tags']
            path:      conduit/apps/articles/models.py:6
        Comment
            fields:    ['body', 'article', 'author']
            path:      conduit/apps/articles/models.py:30
        Tag
            fields:    ['tag', 'slug']
            path:      conduit/apps/articles/models.py:42
        User
            fields:    ['username', 'email', 'is_active', 'is_staff']
            path:      conduit/apps/authentication/models.py:56
            sensitive!!!
        TimestampedModel
            fields:    ['created_at', 'updated_at']
            path:      conduit/apps/core/models.py:4
        Profile
            fields:    ['user', 'bio', 'image', 'follows', 'favorites']
            path:      conduit/apps/profiles/models.py:6
Got 6 objects
6 written to result.json

```

Result:

```
{"path": "conduit/apps/articles/models.py", "line": 6, "object_type": "lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object", "object": "Article", "fields": ["slug", "title", "description", "body", "author", "tags"], "sensitive": false}
{"path": "conduit/apps/articles/models.py", "line": 30, "object_type": "lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object", "object": "Comment", "fields": ["body", "article", "author"], "sensitive": false}
{"path": "conduit/apps/articles/models.py", "line": 42, "object_type": "lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object", "object": "Tag", "fields": ["tag", "slug"], "sensitive": false}
{"path": "conduit/apps/authentication/models.py", "line": 56, "object_type": "lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object", "object": "User", "fields": ["username", "email", "is_active", "is_staff"], "sensitive": true}
{"path": "conduit/apps/core/models.py", "line": 4, "object_type": "lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object", "object": "TimestampedModel", "fields": ["created_at", "updated_at"], "sensitive": false}
{"path": "conduit/apps/profiles/models.py", "line": 6, "object_type": "lib.python3.11.site-packages.semgrep_discovery.rules.python.django-data-object", "object": "Profile", "fields": ["user", "bio", "image", "follows", "favorites"], "sensitive": false}

```








