const load = async ({ locals }) => {
  return {
    user: locals.user,
    session: locals.session
  };
};
export {
  load
};
