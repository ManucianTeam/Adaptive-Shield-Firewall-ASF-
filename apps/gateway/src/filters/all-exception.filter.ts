catch(exception) {

 return response.status(500)
 .json({

   success: false,
 });
}