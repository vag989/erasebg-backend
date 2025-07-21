from tabulate import tabulate


def tabulate_db_entries(model):
    """
    Tabulates the entires of a db
    given a django.db.models object
    """
    queryset = model.objects.all()
    data = list(queryset.values_list())  # Gets all fields
    # Get only direct fields (exclude reverse relations)
    headers = [
        f.name for f in model._meta.get_fields() 
        if not f.auto_created
    ]

    print(f"headers: {headers}")

    return tabulate(data, headers=headers, tablefmt="grid")