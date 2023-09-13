# Register your models here.
class AdminPasswordForm:
    def __init__(self, request):
        self.request = request
        # pass

    def is_valid(self):
        pass

    def get_user(self):
        return self.request.user
