LIST = {
    "calendar.freebusy": {
        "name": "calendar.freebusy",
        "description": "Get free/busy info for given window and calendars",
        "input_schema": {
            "type": "object",
            "required": ["window_start", "window_end"],
            "properties": {
                "window_start": {"type": "string", "format": "date-time"},
                "window_end": {"type": "string", "format": "date-time"},
                "calendars": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    "calendar.create_event": {
        "name": "calendar.create_event",
        "description": "Create an event on the primary calendar",
        "input_schema": {
            "type": "object",
            "required": ["title", "start", "end", "attendees"],
            "properties": {
                "title": {"type": "string"},
                "start": {"type": "string", "format": "date-time"},
                "end": {"type": "string", "format": "date-time"},
                "attendees": {"type": "array", "items": {"type": "string", "format": "email"}},
                "description": {"type": "string"},
                "location": {"type": "string"},
                "conference": {"type": "boolean"},
            },
        },
    },
}
