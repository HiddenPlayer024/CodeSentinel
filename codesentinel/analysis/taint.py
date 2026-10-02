from typing import Dict, List, Set

class TaintConfig:
    SOURCES: Dict[str, List[str]] = {
        "web": ["request.args.get", "request.form.get", "request.get_json", "request.values.get", "flask.request"],
        "cli": ["sys.argv", "argparse", "optparse"],
        "env": ["os.environ", "os.getenv"],
        "file": ["open", "read", "readlines"],
    }
    
    SINKS: Dict[str, Dict[str, float]] = {
        "sql": {
            "execute": 0.8,
            "executemany": 0.8,
        },
        "command": {
            "os.system": 0.8,
            "os.popen": 0.8,
            "subprocess.run": 0.7,
            "subprocess.Popen": 0.7,
            "subprocess.call": 0.7,
            "subprocess.check_call": 0.7,
            "subprocess.check_output": 0.7,
        },
        "path_traversal": {
            "open": 0.7,
            "os.path.join": 0.6,
        },
        "xss": {
            "render_template_string": 0.9,
            "flask.render_template_string": 0.9,
            "django.http.HttpResponse": 0.7,
        },
        "ssrf": {
            "requests.get": 0.8,
            "requests.post": 0.8,
            "requests.request": 0.8,
            "urllib.request.urlopen": 0.8,
        },
        "deserialization": {
            "pickle.loads": 0.9,
            "pickle.load": 0.9,
            "yaml.load": 0.8,
        }
    }
    
    SANITIZERS: Dict[str, List[str]] = {
        "sql": ["escape_string", "re.escape", "quote"],
        "command": ["shlex.quote"],
        "path_traversal": ["os.path.abspath", "os.path.basename", "werkzeug.utils.secure_filename"],
        "xss": ["escape", "html.escape", "flask.escape"],
        "ssrf": ["urllib.parse.urlparse"],
    }

    @classmethod
    def get_sources(cls, category: str = None) -> List[str]:
        if category:
            return cls.SOURCES.get(category, [])
        return [source for sources in cls.SOURCES.values() for source in sources]

    @classmethod
    def get_sinks(cls, category: str = None) -> Dict[str, float]:
        if category:
            return cls.SINKS.get(category, {})
        return {sink: weight for sinks in cls.SINKS.values() for sink, weight in sinks.items()}

    @classmethod
    def get_sanitizers(cls, category: str = None) -> List[str]:
        if category:
            return cls.SANITIZERS.get(category, [])
        return [sanitizer for sanitizers in cls.SANITIZERS.values() for sanitizer in sanitizers]
    
    @classmethod
    def is_sanitizer(cls, func_name: str, category: str = None) -> bool:
        if func_name == "sanitize": 
            return False # explicitly do not broadly trust functions named 'sanitize()'
        sanitizers = cls.get_sanitizers(category)
        return func_name in sanitizers
