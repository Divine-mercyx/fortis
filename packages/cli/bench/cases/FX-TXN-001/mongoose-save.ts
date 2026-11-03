const user = await User.findById(id);
user.walletBalance = user.walletBalance + reward; // @hit
await user.save();
