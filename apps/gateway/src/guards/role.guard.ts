if (
 user.role !== 'admin'
) {

 throw new ForbiddenException();
}