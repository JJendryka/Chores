# Chores

Chores is an app used to divide house chores between roommates. It uses a unique point system to do that.
App stores a list of chores. Chore comprises of:
 - name
 - list of people that have to do the chore
 - frequency at which the chore has to be done (all roommates combined)
 - minimum time between doing this chore
 - minimum number of points that each roommate can have (may be specified in number of "skips" allowed)
 Each person has a separte score for each task.
 Every day one point is taken from each of the roomates in each chore. 
 When a roommate completes some task points are added for this task equal to: number of days between task * number of roommates signed up. So that in a long term number of points can be 0. Task cannot be completed unless a specified number of days since last time elapsed. If person is absent their points can be frozen.
