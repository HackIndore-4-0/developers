"""Tag assets automatically based on Acunetix detected technologies."""

from typing import List


def infer_asset_tags(technologies: List[str]) -> List[str]:
    tags = []
    for tech in technologies:
        t = tech.lower()
        if "wordpress" in t:
            tags.append("cms")
        elif "nginx" in t or "apache" in t:
            tags.append("web-server")
        elif "react" in t or "vue" in t or "next" in t:
            tags.append("frontend-spa")
    return list(set(tags))
